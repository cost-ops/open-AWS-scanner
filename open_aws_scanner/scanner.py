"""
Open AWS Scanner - Simplified AWS waste detection tool.
No admin, no Keycloak, no multi-tenant. Just point at your AWS account and scan.
"""
import boto3
import json
import os
import random
from datetime import datetime, timezone, timedelta
from .database import SessionLocal, ScanResult, ScanRun

STAGE_MODE = os.getenv("STAGE_MODE", "false").lower() == "true"


def get_aws_session(region):
    """Get a boto3 session — uses role assumption if configured, otherwise default credentials."""
    role_arn = os.getenv("AWS_ROLE_ARN", "").strip()
    external_id = os.getenv("AWS_EXTERNAL_ID", "").strip()

    if role_arn:
        sts = boto3.client("sts", region_name=region)
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="open-aws-scanner",
            ExternalId=external_id or "open-aws-scanner",
            DurationSeconds=3600,
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    else:
        return boto3.Session(region_name=region)


# --- Individual Scanners ---

def get_unused_ebs_volumes(ec2):
    findings = []
    volumes = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])
    for vol in volumes["Volumes"]:
        name = next((t["Value"] for t in vol.get("Tags", []) if t["Key"] == "Name"), vol["VolumeId"])
        findings.append({
            "resource_id": vol["VolumeId"],
            "resource_name": name,
            "resource_type": "EBS_Volume",
            "reason": "Volume is not attached to any instance",
            "estimated_monthly_savings": round(vol["Size"] * 0.08, 2),
        })
    return findings


def get_unused_elastic_ips(ec2):
    findings = []
    for eip in ec2.describe_addresses()["Addresses"]:
        if not eip.get("AssociationId"):
            name = next((t["Value"] for t in eip.get("Tags", []) if t["Key"] == "Name"), eip["PublicIp"])
            findings.append({
                "resource_id": eip["AllocationId"],
                "resource_name": name,
                "resource_type": "Elastic_IP",
                "reason": "Unassociated Elastic IP",
                "estimated_monthly_savings": 3.65,
            })
    return findings


def get_idle_ec2_instances(ec2, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    instances = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
    for res in instances["Reservations"]:
        for inst in res["Instances"]:
            instance_id = inst["InstanceId"]
            tags_list = inst.get("Tags", [])
            name = next((t["Value"] for t in tags_list if t["Key"] == "Name"), instance_id)
            resource_tags = {t["Key"]: t["Value"] for t in tags_list if t["Key"] != "Name"}

            cpu_metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=now - timedelta(days=7), EndTime=now,
                Period=86400, Statistics=["Average"],
            )
            cpu_datapoints = cpu_metrics.get("Datapoints", [])
            cpu_avg = sum(dp["Average"] for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else None

            net_in_metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="NetworkIn",
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=now - timedelta(days=7), EndTime=now,
                Period=604800, Statistics=["Sum"],
            )
            net_out_metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="NetworkOut",
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=now - timedelta(days=7), EndTime=now,
                Period=604800, Statistics=["Sum"],
            )
            net_in = net_in_metrics.get("Datapoints", [{}])[0].get("Sum") if net_in_metrics.get("Datapoints") else None
            net_out = net_out_metrics.get("Datapoints", [{}])[0].get("Sum") if net_out_metrics.get("Datapoints") else None

            if cpu_datapoints and all(dp["Average"] < 5.0 for dp in cpu_datapoints):
                findings.append({
                    "resource_id": instance_id,
                    "resource_name": name,
                    "resource_type": "EC2_Instance",
                    "reason": f"CPU avg {cpu_avg:.1f}% over last 7 days",
                    "estimated_monthly_savings": None,
                    "tags": resource_tags,
                    "cpu_avg_percent": round(cpu_avg, 2) if cpu_avg else None,
                    "network_in_bytes": net_in,
                    "network_out_bytes": net_out,
                })
    return findings


def get_idle_rds_instances(rds, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for db_inst in rds.describe_db_instances()["DBInstances"]:
        db_id = db_inst["DBInstanceIdentifier"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/RDS", MetricName="DatabaseConnections",
            Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
            StartTime=now - timedelta(days=7), EndTime=now,
            Period=86400, Statistics=["Average"],
        )
        datapoints = metrics.get("Datapoints", [])
        if datapoints and all(dp["Average"] < 1.0 for dp in datapoints):
            findings.append({
                "resource_id": db_id,
                "resource_name": db_id,
                "resource_type": "RDS_Instance",
                "reason": "Avg connections < 1 over last 7 days",
                "estimated_monthly_savings": None,
            })
    return findings


def get_unused_lambdas(lambda_client, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for fn in lambda_client.list_functions()["Functions"]:
        fn_name = fn["FunctionName"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/Lambda", MetricName="Invocations",
            Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
            StartTime=now - timedelta(days=30), EndTime=now,
            Period=2592000, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": fn_name,
                "resource_name": fn_name,
                "resource_type": "Lambda_Function",
                "reason": "Zero invocations in last 30 days",
                "estimated_monthly_savings": 0,
            })
    return findings


def get_empty_s3_buckets(s3, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/S3", MetricName="NumberOfObjects",
            Dimensions=[
                {"Name": "BucketName", "Value": name},
                {"Name": "StorageType", "Value": "AllStorageTypes"},
            ],
            StartTime=now - timedelta(days=2), EndTime=now,
            Period=86400, Statistics=["Average"],
        )
        datapoints = metrics.get("Datapoints", [])
        if datapoints and all(dp["Average"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": name,
                "resource_name": name,
                "resource_type": "S3_Bucket",
                "reason": "Bucket has zero objects",
                "estimated_monthly_savings": 0,
            })
    return findings


def get_idle_sqs_queues(sqs, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for url in sqs.list_queues().get("QueueUrls", []):
        queue_name = url.split("/")[-1]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/SQS", MetricName="NumberOfMessagesSent",
            Dimensions=[{"Name": "QueueName", "Value": queue_name}],
            StartTime=now - timedelta(days=14), EndTime=now,
            Period=1209600, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": queue_name,
                "resource_name": queue_name,
                "resource_type": "SQS_Queue",
                "reason": "Zero messages sent in last 14 days",
                "estimated_monthly_savings": 0,
            })
    return findings


def get_idle_load_balancers(elbv2, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for lb in elbv2.describe_load_balancers()["LoadBalancers"]:
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb["LoadBalancerName"]
        arn_suffix = "/".join(lb_arn.split("/")[-3:])
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/ApplicationELB", MetricName="RequestCount",
            Dimensions=[{"Name": "LoadBalancer", "Value": arn_suffix}],
            StartTime=now - timedelta(days=7), EndTime=now,
            Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": lb_arn,
                "resource_name": lb_name,
                "resource_type": "Load_Balancer",
                "reason": "Zero requests in last 7 days",
                "estimated_monthly_savings": 16.20,
            })
    return findings


def get_idle_nat_gateways(ec2, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for nat in ec2.describe_nat_gateways(Filter=[{"Name": "state", "Values": ["available"]}])["NatGateways"]:
        nat_id = nat["NatGatewayId"]
        name = next((t["Value"] for t in nat.get("Tags", []) if t["Key"] == "Name"), nat_id)
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/NATGateway", MetricName="BytesOutToDestination",
            Dimensions=[{"Name": "NatGatewayId", "Value": nat_id}],
            StartTime=now - timedelta(days=7), EndTime=now,
            Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": nat_id,
                "resource_name": name,
                "resource_type": "NAT_Gateway",
                "reason": "Zero bytes processed in last 7 days",
                "estimated_monthly_savings": 32.40,
            })
    return findings


def get_idle_dynamodb_tables(dynamodb, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for table_name in dynamodb.list_tables()["TableNames"]:
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/DynamoDB", MetricName="ConsumedReadCapacityUnits",
            Dimensions=[{"Name": "TableName", "Value": table_name}],
            StartTime=now - timedelta(days=14), EndTime=now,
            Period=1209600, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": table_name,
                "resource_name": table_name,
                "resource_type": "DynamoDB_Table",
                "reason": "Zero read capacity consumed in last 14 days",
                "estimated_monthly_savings": None,
            })
    return findings


def get_idle_elasticache_clusters(elasticache, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    for cluster in elasticache.describe_cache_clusters()["CacheClusters"]:
        cluster_id = cluster["CacheClusterId"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/ElastiCache", MetricName="CurrConnections",
            Dimensions=[{"Name": "CacheClusterId", "Value": cluster_id}],
            StartTime=now - timedelta(days=7), EndTime=now,
            Period=86400, Statistics=["Average"],
        )
        datapoints = metrics.get("Datapoints", [])
        if datapoints and all(dp["Average"] < 1.0 for dp in datapoints):
            findings.append({
                "resource_id": cluster_id,
                "resource_name": cluster_id,
                "resource_type": "ElastiCache_Cluster",
                "reason": "Avg connections < 1 over last 7 days",
                "estimated_monthly_savings": None,
            })
    return findings


def get_idle_log_groups(logs):
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    paginator = logs.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        for lg in page["logGroups"]:
            if lg.get("storedBytes", 0) > 0:
                streams = logs.describe_log_streams(
                    logGroupName=lg["logGroupName"],
                    orderBy="LastEventTime", descending=True, limit=1,
                ).get("logStreams", [])
                if streams:
                    last_event = streams[0].get("lastIngestionTime", 0)
                    if last_event and datetime.fromtimestamp(last_event / 1000, tz=timezone.utc) < threshold:
                        findings.append({
                            "resource_id": lg["logGroupName"],
                            "resource_name": lg["logGroupName"],
                            "resource_type": "CloudWatch_Log_Group",
                            "reason": "No log ingestion in last 30 days",
                            "estimated_monthly_savings": round(lg.get("storedBytes", 0) / (1024**3) * 0.03, 2),
                        })
    return findings


def get_orphaned_ebs_snapshots(ec2):
    findings = []
    now = datetime.now(timezone.utc)
    volumes = set()
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page["Volumes"]:
            volumes.add(vol["VolumeId"])
    snap_paginator = ec2.get_paginator("describe_snapshots")
    for page in snap_paginator.paginate(OwnerIds=["self"]):
        for snap in page["Snapshots"]:
            vol_id = snap.get("VolumeId", "")
            if vol_id and vol_id not in volumes:
                snap_id = snap["SnapshotId"]
                size_gb = snap.get("VolumeSize", 0)
                age_days = (now - snap["StartTime"]).days
                name = next((t["Value"] for t in snap.get("Tags", []) if t["Key"] == "Name"), snap_id)
                est_cost = round(size_gb * 0.05, 2)
                if age_days > 30:
                    findings.append({
                        "resource_id": snap_id,
                        "resource_name": name,
                        "resource_type": "EBS_Snapshot",
                        "reason": f"Orphaned snapshot — source volume deleted ({size_gb} GB, {age_days} days old)",
                        "estimated_monthly_savings": est_cost,
                    })
    return findings


def get_idle_sns_topics(sns, cloudwatch):
    findings = []
    now = datetime.now(timezone.utc)
    topics = sns.list_topics().get("Topics", [])
    for topic in topics:
        topic_arn = topic["TopicArn"]
        topic_name = topic_arn.split(":")[-1]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/SNS", MetricName="NumberOfMessagesPublished",
            Dimensions=[{"Name": "TopicName", "Value": topic_name}],
            StartTime=now - timedelta(days=14), EndTime=now,
            Period=1209600, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": topic_arn,
                "resource_name": topic_name,
                "resource_type": "SNS_Topic",
                "reason": "Zero messages published in last 14 days",
                "estimated_monthly_savings": 0,
            })
    return findings


def get_unused_secrets(secretsmanager):
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=90)
    paginator = secretsmanager.get_paginator("list_secrets")
    for page in paginator.paginate():
        for secret in page.get("SecretList", []):
            last_accessed = secret.get("LastAccessedDate")
            secret_name = secret.get("Name", secret.get("ARN", "unknown"))
            if last_accessed and last_accessed < threshold:
                days_unused = (now - last_accessed.replace(tzinfo=timezone.utc)).days
                findings.append({
                    "resource_id": secret.get("ARN", secret_name),
                    "resource_name": secret_name,
                    "resource_type": "Secret",
                    "reason": f"Secret not accessed in {days_unused} days",
                    "estimated_monthly_savings": 0.40,
                })
            elif not last_accessed:
                created = secret.get("CreatedDate")
                if created and created.replace(tzinfo=timezone.utc) < threshold:
                    findings.append({
                        "resource_id": secret.get("ARN", secret_name),
                        "resource_name": secret_name,
                        "resource_type": "Secret",
                        "reason": "Secret has never been accessed",
                        "estimated_monthly_savings": 0.40,
                    })
    return findings


def get_detached_enis(ec2):
    findings = []
    enis = ec2.describe_network_interfaces(
        Filters=[{"Name": "status", "Values": ["available"]}]
    ).get("NetworkInterfaces", [])
    for eni in enis:
        eni_id = eni["NetworkInterfaceId"]
        name = next((t["Value"] for t in eni.get("TagSet", []) if t["Key"] == "Name"), eni_id)
        findings.append({
            "resource_id": eni_id,
            "resource_name": name,
            "resource_type": "ENI",
            "reason": "Network interface is not attached to any instance",
            "estimated_monthly_savings": 0,
        })
    return findings


def get_unused_security_groups(ec2):
    findings = []
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    enis = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
    used_sgs = set()
    for eni in enis:
        for group in eni.get("Groups", []):
            used_sgs.add(group["GroupId"])

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        if sg_name == "default":
            continue
        if sg_id not in used_sgs:
            findings.append({
                "resource_id": sg_id,
                "resource_name": sg_name,
                "resource_type": "Security_Group",
                "reason": "Security group not attached to any network interface",
                "estimated_monthly_savings": 0,
            })
    return findings


def get_mock_findings():
    """Mock findings for stage/demo mode."""
    all_findings = [
        ("EBS_Volume", "vol-0a1b2c3d4e5f", "dev-data-volume", "Volume is not attached to any instance", 12.80),
        ("EBS_Volume", "vol-9z8y7x6w5v4u", "backup-vol-old", "Volume is not attached to any instance", 64.00),
        ("Elastic_IP", "eipalloc-abc123", "staging-ip", "Unassociated Elastic IP", 3.65),
        ("EC2_Instance", "i-0123456789abcdef0", "test-server-bob", "CPU avg < 5% over last 7 days", 85.00),
        ("EC2_Instance", "i-fedcba9876543210", "legacy-worker-node", "CPU avg < 5% over last 7 days", 142.50),
        ("RDS_Instance", "dev-db-unused", "dev-db-unused", "Avg connections < 1 over last 7 days", 95.00),
        ("Lambda_Function", "old-migration-handler", "old-migration-handler", "Zero invocations in last 30 days", 0),
        ("S3_Bucket", "old-backup-bucket-2023", "old-backup-bucket-2023", "Bucket has zero objects", 0),
        ("SQS_Queue", "legacy-event-queue", "legacy-event-queue", "Zero messages sent in last 14 days", 0),
        ("Load_Balancer", "arn:aws:elb:unused-alb", "unused-alb-staging", "Zero requests in last 7 days", 16.20),
        ("NAT_Gateway", "nat-0abc123def456", "dev-nat-gateway", "Zero bytes processed in last 7 days", 32.40),
        ("DynamoDB_Table", "old-session-store", "old-session-store", "Zero read capacity consumed in last 14 days", 25.00),
        ("ElastiCache_Cluster", "redis-staging-001", "redis-staging-001", "Avg connections < 1 over last 7 days", 48.00),
    ]
    selected = random.sample(all_findings, random.randint(5, len(all_findings)))
    return [{"resource_type": r[0], "resource_id": r[1], "resource_name": r[2], "reason": r[3], "estimated_monthly_savings": r[4]} for r in selected]


# --- Main Scanner Entry Point ---

def run_scan():
    """Run a scan using config from environment variables."""
    regions_str = os.getenv("AWS_REGIONS", "us-east-1")
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]

    print(f"[SCAN] Starting scan in regions: {', '.join(regions)}...")

    db = SessionLocal()
    scan_run = ScanRun(status="running")
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    errors = []
    findings = []

    try:
        if STAGE_MODE:
            print("[SCAN] STAGE MODE — using mock data")
            findings = get_mock_findings()
        else:
            for aws_region in regions:
                print(f"[SCAN]   === Region: {aws_region} ===")
                try:
                    session = get_aws_session(aws_region)
                    ec2 = session.client("ec2")
                    cloudwatch = session.client("cloudwatch")
                    rds = session.client("rds")
                    lambda_client = session.client("lambda")
                    s3 = session.client("s3")
                    sqs = session.client("sqs")
                    elbv2 = session.client("elbv2")
                    dynamodb = session.client("dynamodb")
                    elasticache = session.client("elasticache")
                    logs = session.client("logs")
                    sns = session.client("sns")
                    secretsmanager = session.client("secretsmanager")

                    scanners = [
                        ("EBS Volumes", get_unused_ebs_volumes, [ec2]),
                        ("Elastic IPs", get_unused_elastic_ips, [ec2]),
                        ("EBS Snapshots", get_orphaned_ebs_snapshots, [ec2]),
                        ("Detached ENIs", get_detached_enis, [ec2]),
                        ("Unused Security Groups", get_unused_security_groups, [ec2]),
                        ("EC2 Instances", get_idle_ec2_instances, [ec2, cloudwatch]),
                        ("RDS Instances", get_idle_rds_instances, [rds, cloudwatch]),
                        ("Lambda Functions", get_unused_lambdas, [lambda_client, cloudwatch]),
                        ("S3 Buckets (empty)", get_empty_s3_buckets, [s3, cloudwatch]),
                        ("SQS Queues", get_idle_sqs_queues, [sqs, cloudwatch]),
                        ("SNS Topics", get_idle_sns_topics, [sns, cloudwatch]),
                        ("Load Balancers", get_idle_load_balancers, [elbv2, cloudwatch]),
                        ("NAT Gateways", get_idle_nat_gateways, [ec2, cloudwatch]),
                        ("DynamoDB Tables", get_idle_dynamodb_tables, [dynamodb, cloudwatch]),
                        ("ElastiCache Clusters", get_idle_elasticache_clusters, [elasticache, cloudwatch]),
                        ("CloudWatch Log Groups", get_idle_log_groups, [logs]),
                        ("Secrets Manager", get_unused_secrets, [secretsmanager]),
                    ]

                    for name, func, args in scanners:
                        print(f"[SCAN]   Scanning {name}...")
                        try:
                            results = func(*args)
                            for r in results:
                                r["region"] = aws_region
                            findings += results
                            print(f"[SCAN]     {len(results)} issues found")
                        except Exception as e:
                            err_str = str(e)
                            if "SubscriptionRequired" in err_str or "OptInRequired" in err_str:
                                print(f"[SCAN]     {name}: skipped (not enabled)")
                            else:
                                print(f"[SCAN]     ERROR: {e}")
                                errors.append(f"{name} ({aws_region}): {e}")
                except Exception as e:
                    print(f"[SCAN]   ERROR initializing region {aws_region}: {e}")
                    errors.append(f"Region {aws_region}: {e}")

        # Store findings
        for f in findings:
            existing = db.query(ScanResult).filter(
                ScanResult.resource_id == f["resource_id"],
                ScanResult.resource_type == f["resource_type"],
            ).order_by(ScanResult.scanned_at.asc()).first()
            first_seen = existing.first_seen_at or existing.scanned_at if existing else None

            db.add(ScanResult(
                scan_run_id=scan_run.id,
                resource_id=f["resource_id"],
                resource_name=f.get("resource_name"),
                resource_type=f["resource_type"],
                reason=f.get("reason"),
                estimated_monthly_savings=f.get("estimated_monthly_savings"),
                tags=json.dumps(f["tags"]) if f.get("tags") else None,
                cpu_avg_percent=f.get("cpu_avg_percent"),
                memory_avg_percent=f.get("memory_avg_percent"),
                network_in_bytes=f.get("network_in_bytes"),
                network_out_bytes=f.get("network_out_bytes"),
                region=f.get("region"),
                status="open",
                first_seen_at=first_seen or datetime.now(timezone.utc),
            ))

        scan_run.status = "completed" if not errors else "completed_with_errors"
        scan_run.findings_count = len(findings)
        scan_run.errors = "\n".join(errors) if errors else None
        scan_run.completed_at = datetime.now(timezone.utc)
        db.commit()
        print(f"[SCAN] Complete. {len(findings)} total issues found.")

    except Exception as e:
        print(f"[SCAN] FATAL error: {e}")
        scan_run.status = "failed"
        scan_run.errors = str(e)
        scan_run.completed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()

    return findings
