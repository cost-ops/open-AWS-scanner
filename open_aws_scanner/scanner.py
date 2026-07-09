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


# --- Additional Scanners (advanced) ---

def get_idle_ecs_services(ecs, cloudwatch):
    """Find ECS services with zero running tasks or no CPU usage."""
    findings = []
    now = datetime.now(timezone.utc)
    clusters = ecs.list_clusters().get("clusterArns", [])
    for cluster_arn in clusters:
        cluster_name = cluster_arn.split("/")[-1]
        services = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
        if not services:
            continue
        described = ecs.describe_services(cluster=cluster_arn, services=services[:10]).get("services", [])
        for svc in described:
            svc_name = svc["serviceName"]
            running = svc.get("runningCount", 0)
            desired = svc.get("desiredCount", 0)

            if running == 0 and desired == 0:
                findings.append({
                    "resource_id": svc["serviceArn"],
                    "resource_name": f"{cluster_name}/{svc_name}",
                    "resource_type": "ECS_Service",
                    "reason": "Service has zero desired and running tasks",
                    "estimated_monthly_savings": 0,
                })
                continue

            metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/ECS", MetricName="CPUUtilization",
                Dimensions=[
                    {"Name": "ClusterName", "Value": cluster_name},
                    {"Name": "ServiceName", "Value": svc_name},
                ],
                StartTime=now - timedelta(days=7), EndTime=now,
                Period=604800, Statistics=["Average"],
            )
            datapoints = metrics.get("Datapoints", [])
            if datapoints and all(dp["Average"] < 2.0 for dp in datapoints):
                findings.append({
                    "resource_id": svc["serviceArn"],
                    "resource_name": f"{cluster_name}/{svc_name}",
                    "resource_type": "ECS_Service",
                    "reason": f"CPU avg < 2% over last 7 days ({running} running tasks)",
                    "estimated_monthly_savings": None,
                })
    return findings


def get_idle_ecr_repos(ecr):
    """Find ECR repositories with no image pulls in last 30 days."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    paginator = ecr.get_paginator("describe_repositories")
    for page in paginator.paginate():
        for repo in page.get("repositories", []):
            repo_name = repo["repositoryName"]
            try:
                images = ecr.describe_images(
                    repositoryName=repo_name,
                    filter={"tagStatus": "ANY"},
                    maxResults=5,
                ).get("imageDetails", [])
            except Exception:
                continue

            if not images:
                findings.append({
                    "resource_id": repo.get("repositoryArn", repo_name),
                    "resource_name": repo_name,
                    "resource_type": "ECR_Repository",
                    "reason": "Repository has no images",
                    "estimated_monthly_savings": 0,
                })
                continue

            last_pull = None
            total_size = 0
            for img in images:
                pull_time = img.get("lastRecordedPullTime")
                if pull_time and (not last_pull or pull_time > last_pull):
                    last_pull = pull_time
                total_size += img.get("imageSizeInBytes", 0)

            if last_pull and last_pull < threshold:
                days_idle = (now - last_pull.replace(tzinfo=timezone.utc)).days
                size_gb = total_size / (1024**3)
                est_cost = round(size_gb * 0.10, 2)
                findings.append({
                    "resource_id": repo.get("repositoryArn", repo_name),
                    "resource_name": repo_name,
                    "resource_type": "ECR_Repository",
                    "reason": f"No image pulls in {days_idle} days ({size_gb:.2f} GB stored)",
                    "estimated_monthly_savings": est_cost,
                })
            elif not last_pull and images:
                size_gb = total_size / (1024**3)
                est_cost = round(size_gb * 0.10, 2)
                findings.append({
                    "resource_id": repo.get("repositoryArn", repo_name),
                    "resource_name": repo_name,
                    "resource_type": "ECR_Repository",
                    "reason": f"Images never pulled ({size_gb:.2f} GB stored)",
                    "estimated_monthly_savings": est_cost,
                })
    return findings


def get_idle_cloudfront_distributions(cloudfront, cloudwatch):
    """Find CloudFront distributions with no requests."""
    findings = []
    now = datetime.now(timezone.utc)
    dists = cloudfront.list_distributions().get("DistributionList", {}).get("Items", [])
    for dist in dists:
        dist_id = dist["Id"]
        domain = dist.get("DomainName", dist_id)
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/CloudFront", MetricName="Requests",
            Dimensions=[
                {"Name": "DistributionId", "Value": dist_id},
                {"Name": "Region", "Value": "Global"},
            ],
            StartTime=now - timedelta(days=7), EndTime=now,
            Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": dist_id,
                "resource_name": domain,
                "resource_type": "CloudFront_Distribution",
                "reason": "Zero requests in last 7 days",
                "estimated_monthly_savings": None,
            })
    return findings


def get_inactive_s3_buckets(s3, cloudwatch):
    """Find S3 buckets with no GET/PUT requests in the last 30 days."""
    findings = []
    now = datetime.now(timezone.utc)
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        get_metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/S3", MetricName="GetRequests",
            Dimensions=[{"Name": "BucketName", "Value": name}, {"Name": "FilterId", "Value": "EntireBucket"}],
            StartTime=now - timedelta(days=30), EndTime=now, Period=2592000, Statistics=["Sum"],
        )
        put_metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/S3", MetricName="PutRequests",
            Dimensions=[{"Name": "BucketName", "Value": name}, {"Name": "FilterId", "Value": "EntireBucket"}],
            StartTime=now - timedelta(days=30), EndTime=now, Period=2592000, Statistics=["Sum"],
        )
        get_points = get_metrics.get("Datapoints", [])
        put_points = put_metrics.get("Datapoints", [])
        has_get_data = len(get_points) > 0
        has_put_data = len(put_points) > 0
        if has_get_data or has_put_data:
            total_gets = sum(dp["Sum"] for dp in get_points) if get_points else 0
            total_puts = sum(dp["Sum"] for dp in put_points) if put_points else 0
            if total_gets == 0 and total_puts == 0:
                size_metrics = cloudwatch.get_metric_statistics(
                    Namespace="AWS/S3", MetricName="BucketSizeBytes",
                    Dimensions=[{"Name": "BucketName", "Value": name}, {"Name": "StorageType", "Value": "StandardStorage"}],
                    StartTime=now - timedelta(days=2), EndTime=now, Period=86400, Statistics=["Average"],
                )
                size_points = size_metrics.get("Datapoints", [])
                size_gb = (size_points[-1]["Average"] / (1024**3)) if size_points else 0
                est_cost = round(size_gb * 0.023, 2)
                findings.append({
                    "resource_id": name, "resource_name": name, "resource_type": "S3_Bucket_Inactive",
                    "reason": f"Zero GET/PUT requests in last 30 days ({size_gb:.1f} GB stored)",
                    "estimated_monthly_savings": est_cost,
                })
    return findings


def get_stale_s3_buckets(s3):
    """Find S3 buckets where all objects are older than 90 days."""
    findings = []
    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(days=90)
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            response = s3.list_objects_v2(Bucket=name, MaxKeys=100)
            objects = response.get("Contents", [])
            if not objects:
                continue
            newest_modified = max(obj["LastModified"] for obj in objects)
            total_size = sum(obj["Size"] for obj in objects)
            if newest_modified < stale_threshold:
                days_stale = (now - newest_modified).days
                is_truncated = response.get("IsTruncated", False)
                size_gb = total_size / (1024**3)
                est_cost = round(size_gb * 0.023, 2)
                size_label = f"{size_gb:.2f} GB" if size_gb >= 1 else f"{total_size / (1024**2):.1f} MB"
                truncated_note = " (sampled 100 objects)" if is_truncated else ""
                findings.append({
                    "resource_id": name, "resource_name": name, "resource_type": "S3_Bucket_Stale",
                    "reason": f"No objects modified in {days_stale} days — {size_label} stored{truncated_note}",
                    "estimated_monthly_savings": est_cost,
                })
        except Exception:
            continue
    return findings


def get_idle_redshift_clusters(redshift, cloudwatch):
    """Find Redshift clusters with no query activity."""
    findings = []
    now = datetime.now(timezone.utc)
    clusters = redshift.describe_clusters().get("Clusters", [])
    for cluster in clusters:
        cluster_id = cluster["ClusterIdentifier"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/Redshift", MetricName="DatabaseConnections",
            Dimensions=[{"Name": "ClusterIdentifier", "Value": cluster_id}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=86400, Statistics=["Average"],
        )
        datapoints = metrics.get("Datapoints", [])
        if datapoints and all(dp["Average"] < 1.0 for dp in datapoints):
            node_type = cluster.get("NodeType", "unknown")
            num_nodes = cluster.get("NumberOfNodes", 1)
            findings.append({
                "resource_id": cluster_id, "resource_name": cluster_id, "resource_type": "Redshift_Cluster",
                "reason": f"Avg connections < 1 over last 7 days ({node_type} x{num_nodes})",
                "estimated_monthly_savings": None,
            })
    return findings


def get_idle_opensearch_domains(opensearch, cloudwatch):
    """Find OpenSearch domains with no search or indexing activity."""
    findings = []
    now = datetime.now(timezone.utc)
    domains = opensearch.list_domain_names().get("DomainNames", [])
    for domain in domains:
        domain_name = domain["DomainName"]
        search_metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/ES", MetricName="SearchRate",
            Dimensions=[{"Name": "DomainName", "Value": domain_name}, {"Name": "ClientId", "Value": "*"}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
        )
        index_metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/ES", MetricName="IndexingRate",
            Dimensions=[{"Name": "DomainName", "Value": domain_name}, {"Name": "ClientId", "Value": "*"}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
        )
        search_points = search_metrics.get("Datapoints", [])
        index_points = index_metrics.get("Datapoints", [])
        total_searches = sum(dp["Sum"] for dp in search_points) if search_points else 0
        total_indexes = sum(dp["Sum"] for dp in index_points) if index_points else 0
        if (search_points or index_points) and total_searches == 0 and total_indexes == 0:
            findings.append({
                "resource_id": domain_name, "resource_name": domain_name, "resource_type": "OpenSearch_Domain",
                "reason": "Zero search and indexing operations in last 7 days",
                "estimated_monthly_savings": None,
            })
    return findings


def get_idle_eks_nodegroups(eks, cloudwatch):
    """Find EKS node groups with very low CPU utilization."""
    findings = []
    clusters = eks.list_clusters().get("clusters", [])
    for cluster_name in clusters:
        nodegroups = eks.list_nodegroups(clusterName=cluster_name).get("nodegroups", [])
        for ng_name in nodegroups:
            ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name).get("nodegroup", {})
            desired = ng.get("scalingConfig", {}).get("desiredSize", 0)
            if desired == 0:
                findings.append({
                    "resource_id": ng.get("nodegroupArn", f"{cluster_name}/{ng_name}"),
                    "resource_name": f"{cluster_name}/{ng_name}", "resource_type": "EKS_NodeGroup",
                    "reason": "Node group scaled to zero desired nodes", "estimated_monthly_savings": 0,
                })
    return findings


def get_idle_apprunner_services(apprunner, cloudwatch):
    """Find App Runner services with no traffic."""
    findings = []
    now = datetime.now(timezone.utc)
    services = apprunner.list_services().get("ServiceSummaryList", [])
    for svc in services:
        svc_name = svc["ServiceName"]
        svc_arn = svc["ServiceArn"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/AppRunner", MetricName="RequestCount",
            Dimensions=[{"Name": "ServiceName", "Value": svc_name}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": svc_arn, "resource_name": svc_name, "resource_type": "AppRunner_Service",
                "reason": "Zero requests in last 7 days", "estimated_monthly_savings": None,
            })
    return findings


def get_idle_efs_filesystems(efs, cloudwatch):
    """Find EFS file systems with zero client connections."""
    findings = []
    now = datetime.now(timezone.utc)
    filesystems = efs.describe_file_systems().get("FileSystems", [])
    for fs in filesystems:
        fs_id = fs["FileSystemId"]
        name = fs.get("Name", fs_id)
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/EFS", MetricName="ClientConnections",
            Dimensions=[{"Name": "FileSystemId", "Value": fs_id}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if datapoints and all(dp["Sum"] == 0 for dp in datapoints):
            size_bytes = fs.get("SizeInBytes", {}).get("Value", 0)
            size_gb = size_bytes / (1024**3)
            est_cost = round(size_gb * 0.30, 2)
            findings.append({
                "resource_id": fs_id, "resource_name": name, "resource_type": "EFS_FileSystem",
                "reason": f"Zero client connections in last 7 days ({size_gb:.2f} GB)",
                "estimated_monthly_savings": est_cost,
            })
    return findings


def get_idle_fsx_filesystems(fsx):
    """Find FSx file systems that appear unused."""
    findings = []
    now = datetime.now(timezone.utc)
    filesystems = fsx.describe_file_systems().get("FileSystems", [])
    for fs in filesystems:
        fs_id = fs["FileSystemId"]
        fs_type = fs.get("FileSystemType", "unknown")
        storage_gb = fs.get("StorageCapacity", 0)
        created = fs.get("CreationTime")
        if created:
            age_days = (now - created.replace(tzinfo=timezone.utc)).days
            if age_days > 90:
                est_cost = round(storage_gb * 0.13, 2)
                findings.append({
                    "resource_id": fs_id, "resource_name": fs_id, "resource_type": "FSx_FileSystem",
                    "reason": f"{fs_type} filesystem — {storage_gb} GB, {age_days} days old (verify usage)",
                    "estimated_monthly_savings": est_cost,
                })
    return findings


def get_idle_kinesis_streams(kinesis, cloudwatch):
    """Find Kinesis streams with no incoming records."""
    findings = []
    now = datetime.now(timezone.utc)
    streams = kinesis.list_streams().get("StreamNames", [])
    for stream_name in streams:
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/Kinesis", MetricName="IncomingRecords",
            Dimensions=[{"Name": "StreamName", "Value": stream_name}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            try:
                desc = kinesis.describe_stream_summary(StreamName=stream_name)
                shards = desc.get("StreamDescriptionSummary", {}).get("OpenShardCount", 1)
                est_cost = round(shards * 36.0, 2)
            except Exception:
                est_cost = None
            findings.append({
                "resource_id": stream_name, "resource_name": stream_name, "resource_type": "Kinesis_Stream",
                "reason": "Zero incoming records in last 7 days", "estimated_monthly_savings": est_cost,
            })
    return findings


def get_idle_sagemaker_endpoints(sagemaker, cloudwatch):
    """Find SageMaker endpoints with no invocations."""
    findings = []
    now = datetime.now(timezone.utc)
    endpoints = sagemaker.list_endpoints(StatusEquals="InService").get("Endpoints", [])
    for ep in endpoints:
        ep_name = ep["EndpointName"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/SageMaker", MetricName="Invocations",
            Dimensions=[{"Name": "EndpointName", "Value": ep_name}],
            StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": ep.get("EndpointArn", ep_name), "resource_name": ep_name,
                "resource_type": "SageMaker_Endpoint",
                "reason": "Zero invocations in last 7 days", "estimated_monthly_savings": None,
            })
    return findings


def get_idle_sagemaker_notebooks(sagemaker):
    """Find SageMaker notebook instances in service but potentially unused."""
    findings = []
    now = datetime.now(timezone.utc)
    notebooks = sagemaker.list_notebook_instances(StatusEquals="InService").get("NotebookInstances", [])
    for nb in notebooks:
        nb_name = nb["NotebookInstanceName"]
        instance_type = nb.get("InstanceType", "unknown")
        last_modified = nb.get("LastModifiedTime")
        if last_modified:
            days_idle = (now - last_modified.replace(tzinfo=timezone.utc)).days
            if days_idle > 7:
                findings.append({
                    "resource_id": nb.get("NotebookInstanceArn", nb_name), "resource_name": nb_name,
                    "resource_type": "SageMaker_Notebook",
                    "reason": f"Running ({instance_type}) but not modified in {days_idle} days",
                    "estimated_monthly_savings": None,
                })
    return findings


def get_idle_api_gateways(apigateway, cloudwatch):
    """Find API Gateway REST APIs with no requests."""
    findings = []
    now = datetime.now(timezone.utc)
    apis = apigateway.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api["id"]
        api_name = api.get("name", api_id)
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/ApiGateway", MetricName="Count",
            Dimensions=[{"Name": "ApiName", "Value": api_name}],
            StartTime=now - timedelta(days=14), EndTime=now, Period=1209600, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": api_id, "resource_name": api_name, "resource_type": "API_Gateway",
                "reason": "Zero API calls in last 14 days", "estimated_monthly_savings": 0,
            })
    return findings


def get_idle_step_functions(sfn, cloudwatch):
    """Find Step Functions state machines with no executions."""
    findings = []
    now = datetime.now(timezone.utc)
    machines = sfn.list_state_machines().get("stateMachines", [])
    for sm in machines:
        sm_name = sm["name"]
        sm_arn = sm["stateMachineArn"]
        metrics = cloudwatch.get_metric_statistics(
            Namespace="AWS/States", MetricName="ExecutionsStarted",
            Dimensions=[{"Name": "StateMachineArn", "Value": sm_arn}],
            StartTime=now - timedelta(days=30), EndTime=now, Period=2592000, Statistics=["Sum"],
        )
        datapoints = metrics.get("Datapoints", [])
        if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
            findings.append({
                "resource_id": sm_arn, "resource_name": sm_name, "resource_type": "StepFunctions_StateMachine",
                "reason": "Zero executions in last 30 days", "estimated_monthly_savings": 0,
            })
    return findings


def get_idle_glue_jobs(glue):
    """Find Glue jobs that haven't run recently."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    jobs = glue.get_jobs().get("Jobs", [])
    for job in jobs:
        job_name = job["Name"]
        runs = glue.get_job_runs(JobName=job_name, MaxResults=1).get("JobRuns", [])
        if not runs:
            findings.append({
                "resource_id": job_name, "resource_name": job_name, "resource_type": "Glue_Job",
                "reason": "Glue job has never been executed", "estimated_monthly_savings": 0,
            })
        elif runs[0].get("StartedOn", now) < threshold:
            days_since = (now - runs[0]["StartedOn"].replace(tzinfo=timezone.utc)).days
            findings.append({
                "resource_id": job_name, "resource_name": job_name, "resource_type": "Glue_Job",
                "reason": f"Last execution was {days_since} days ago", "estimated_monthly_savings": 0,
            })
    return findings


def get_idle_vpn_connections(ec2):
    """Find VPN connections with DOWN status."""
    findings = []
    vpns = ec2.describe_vpn_connections().get("VpnConnections", [])
    for vpn in vpns:
        vpn_id = vpn["VpnConnectionId"]
        name = next((t["Value"] for t in vpn.get("Tags", []) if t["Key"] == "Name"), vpn_id)
        state = vpn.get("State", "")
        if state == "available":
            tunnels = vpn.get("VgwTelemetry", [])
            all_down = all(t.get("Status") == "DOWN" for t in tunnels) if tunnels else False
            if all_down:
                findings.append({
                    "resource_id": vpn_id, "resource_name": name, "resource_type": "VPN_Connection",
                    "reason": "All VPN tunnels are DOWN", "estimated_monthly_savings": 36.50,
                })
    return findings


def get_idle_transit_gateways(ec2):
    """Find Transit Gateways with no attachments."""
    findings = []
    tgws = ec2.describe_transit_gateways().get("TransitGateways", [])
    for tgw in tgws:
        tgw_id = tgw["TransitGatewayId"]
        name = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), tgw_id)
        attachments = ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        ).get("TransitGatewayAttachments", [])
        if not attachments:
            findings.append({
                "resource_id": tgw_id, "resource_name": name, "resource_type": "Transit_Gateway",
                "reason": "Transit Gateway has no attachments", "estimated_monthly_savings": 36.00,
            })
    return findings


def get_unused_kms_keys(kms):
    """Find KMS keys that haven't been used recently."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=90)
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page.get("Keys", []):
            key_id = key["KeyId"]
            try:
                metadata = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if metadata.get("KeyManager") == "AWS":
                    continue
                if metadata.get("KeyState") != "Enabled":
                    continue
                key_alias = key_id
                aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                if aliases:
                    key_alias = aliases[0].get("AliasName", key_id)
                created = metadata.get("CreationDate")
                if created and created.replace(tzinfo=timezone.utc) < threshold:
                    findings.append({
                        "resource_id": key_id, "resource_name": key_alias, "resource_type": "KMS_Key",
                        "reason": "Customer-managed key — verify if still in use ($1/mo)",
                        "estimated_monthly_savings": 1.00,
                    })
            except Exception:
                continue
    return findings


def get_idle_route53_zones(route53):
    """Find Route 53 hosted zones with no record sets besides default NS/SOA."""
    findings = []
    zones = route53.list_hosted_zones().get("HostedZones", [])
    for zone in zones:
        zone_id = zone["Id"].split("/")[-1]
        zone_name = zone["Name"]
        record_count = zone.get("ResourceRecordSetCount", 0)
        if record_count <= 2:
            findings.append({
                "resource_id": zone_id, "resource_name": zone_name, "resource_type": "Route53_Zone",
                "reason": "Hosted zone has no custom records (only NS/SOA)",
                "estimated_monthly_savings": 0.50,
            })
    return findings


def get_idle_eventbridge_rules(events):
    """Find EventBridge rules that are disabled."""
    findings = []
    rules = events.list_rules().get("Rules", [])
    for rule in rules:
        rule_name = rule["Name"]
        state = rule.get("State", "")
        if state == "DISABLED":
            findings.append({
                "resource_id": rule.get("Arn", rule_name), "resource_name": rule_name,
                "resource_type": "EventBridge_Rule",
                "reason": "Rule is disabled", "estimated_monthly_savings": 0,
            })
    return findings


def get_idle_emr_clusters(emr):
    """Find EMR clusters that are waiting/idle."""
    findings = []
    clusters = emr.list_clusters(ClusterStates=["WAITING"]).get("Clusters", [])
    for cluster in clusters:
        cluster_id = cluster["Id"]
        cluster_name = cluster.get("Name", cluster_id)
        findings.append({
            "resource_id": cluster_id, "resource_name": cluster_name, "resource_type": "EMR_Cluster",
            "reason": "Cluster in WAITING state (idle, no running steps)",
            "estimated_monthly_savings": None,
        })
    return findings


def get_unused_amis(ec2):
    """Find owned AMIs not used by any running instance."""
    findings = []
    images = ec2.describe_images(Owners=["self"]).get("Images", [])
    instances = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    ).get("Reservations", [])
    used_amis = set()
    for res in instances:
        for inst in res["Instances"]:
            used_amis.add(inst.get("ImageId"))
    for img in images:
        ami_id = img["ImageId"]
        if ami_id not in used_amis:
            name = img.get("Name", ami_id)
            total_size = sum(
                bdm.get("Ebs", {}).get("VolumeSize", 0)
                for bdm in img.get("BlockDeviceMappings", []) if "Ebs" in bdm
            )
            est_cost = round(total_size * 0.05, 2)
            findings.append({
                "resource_id": ami_id, "resource_name": name, "resource_type": "AMI",
                "reason": f"AMI not used by any instance ({total_size} GB snapshots)",
                "estimated_monthly_savings": est_cost,
            })
    return findings


def get_idle_neptune_clusters(neptune, cloudwatch):
    """Find Neptune clusters with no connections."""
    findings = []
    now = datetime.now(timezone.utc)
    try:
        clusters = neptune.describe_db_clusters().get("DBClusters", [])
        for cluster in clusters:
            if cluster.get("Engine") != "neptune":
                continue
            cluster_id = cluster["DBClusterIdentifier"]
            gremlin_metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/Neptune", MetricName="GremlinRequestsPerSec",
                Dimensions=[{"Name": "DBClusterIdentifier", "Value": cluster_id}],
                StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
            )
            g_points = gremlin_metrics.get("Datapoints", [])
            if not g_points or all(dp["Sum"] == 0 for dp in g_points):
                findings.append({
                    "resource_id": cluster_id, "resource_name": cluster_id,
                    "resource_type": "Neptune_Cluster",
                    "reason": "Zero graph queries in last 7 days", "estimated_monthly_savings": None,
                })
    except Exception:
        pass
    return findings


def get_idle_docdb_clusters(docdb, cloudwatch):
    """Find DocumentDB clusters with no connections."""
    findings = []
    now = datetime.now(timezone.utc)
    try:
        clusters = docdb.describe_db_clusters().get("DBClusters", [])
        for cluster in clusters:
            if cluster.get("Engine") != "docdb":
                continue
            cluster_id = cluster["DBClusterIdentifier"]
            metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/DocDB", MetricName="DatabaseConnections",
                Dimensions=[{"Name": "DBClusterIdentifier", "Value": cluster_id}],
                StartTime=now - timedelta(days=7), EndTime=now, Period=86400, Statistics=["Average"],
            )
            datapoints = metrics.get("Datapoints", [])
            if datapoints and all(dp["Average"] < 1.0 for dp in datapoints):
                findings.append({
                    "resource_id": cluster_id, "resource_name": cluster_id,
                    "resource_type": "DocumentDB_Cluster",
                    "reason": "Avg connections < 1 over last 7 days", "estimated_monthly_savings": None,
                })
    except Exception:
        pass
    return findings


def get_idle_lightsail_instances(lightsail, cloudwatch):
    """Find Lightsail instances with low CPU."""
    findings = []
    now = datetime.now(timezone.utc)
    try:
        instances = lightsail.get_instances().get("instances", [])
        for inst in instances:
            inst_name = inst["name"]
            metrics = lightsail.get_instance_metric_data(
                instanceName=inst_name, metricName="CPUUtilization",
                period=86400, startTime=now - timedelta(days=7), endTime=now,
                unit="Percent", statistics=["Average"],
            ).get("metricData", [])
            if metrics and all(dp["average"] < 5.0 for dp in metrics if "average" in dp):
                bundle = inst.get("bundleId", "unknown")
                findings.append({
                    "resource_id": inst.get("arn", inst_name), "resource_name": inst_name,
                    "resource_type": "Lightsail_Instance",
                    "reason": f"CPU avg < 5% over last 7 days ({bundle})",
                    "estimated_monthly_savings": None,
                })
    except Exception:
        pass
    return findings


def get_idle_waf_acls(wafv2):
    """Find WAF Web ACLs not associated with any resource."""
    findings = []
    try:
        for scope in ["REGIONAL", "CLOUDFRONT"]:
            acls = wafv2.list_web_acls(Scope=scope).get("WebACLs", [])
            for acl in acls:
                acl_name = acl["Name"]
                acl_id = acl["Id"]
                acl_arn = acl.get("ARN", "")
                resources = wafv2.list_resources_for_web_acl(WebACLArn=acl_arn).get("ResourceArns", [])
                if not resources:
                    findings.append({
                        "resource_id": acl_id, "resource_name": acl_name, "resource_type": "WAF_WebACL",
                        "reason": f"WAF Web ACL ({scope}) not attached to any resource",
                        "estimated_monthly_savings": 5.00,
                    })
    except Exception:
        pass
    return findings


def get_idle_global_accelerator(globalaccelerator, cloudwatch):
    """Find Global Accelerators with no traffic."""
    findings = []
    now = datetime.now(timezone.utc)
    try:
        accelerators = globalaccelerator.list_accelerators().get("Accelerators", [])
        for accel in accelerators:
            accel_arn = accel["AcceleratorArn"]
            accel_name = accel.get("Name", accel_arn)
            metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/GlobalAccelerator", MetricName="ProcessedBytesIn",
                Dimensions=[{"Name": "Accelerator", "Value": accel_arn}],
                StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
            )
            datapoints = metrics.get("Datapoints", [])
            if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
                findings.append({
                    "resource_id": accel_arn, "resource_name": accel_name,
                    "resource_type": "Global_Accelerator",
                    "reason": "Zero bytes processed in last 7 days", "estimated_monthly_savings": 18.00,
                })
    except Exception:
        pass
    return findings


def get_idle_codepipeline(codepipeline):
    """Find CodePipeline pipelines with no recent executions."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    try:
        pipelines = codepipeline.list_pipelines().get("pipelines", [])
        for p in pipelines:
            p_name = p["name"]
            executions = codepipeline.list_pipeline_executions(
                pipelineName=p_name, maxResults=1
            ).get("pipelineExecutionSummaries", [])
            if not executions:
                findings.append({
                    "resource_id": p_name, "resource_name": p_name, "resource_type": "CodePipeline",
                    "reason": "Pipeline has never been executed", "estimated_monthly_savings": 1.00,
                })
            elif executions[0].get("startTime", now) < threshold:
                days = (now - executions[0]["startTime"].replace(tzinfo=timezone.utc)).days
                findings.append({
                    "resource_id": p_name, "resource_name": p_name, "resource_type": "CodePipeline",
                    "reason": f"Last execution was {days} days ago", "estimated_monthly_savings": 1.00,
                })
    except Exception:
        pass
    return findings


def get_idle_codebuild_projects(codebuild):
    """Find CodeBuild projects with no recent builds."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    try:
        projects = codebuild.list_projects().get("projects", [])
        for proj_name in projects:
            builds = codebuild.list_builds_for_project(
                projectName=proj_name, sortOrder="DESCENDING"
            ).get("ids", [])
            if not builds:
                findings.append({
                    "resource_id": proj_name, "resource_name": proj_name, "resource_type": "CodeBuild_Project",
                    "reason": "Project has never been built", "estimated_monthly_savings": 0,
                })
            else:
                build_detail = codebuild.batch_get_builds(ids=[builds[0]]).get("builds", [])
                if build_detail:
                    end_time = build_detail[0].get("endTime")
                    if end_time and end_time.replace(tzinfo=timezone.utc) < threshold:
                        days = (now - end_time.replace(tzinfo=timezone.utc)).days
                        findings.append({
                            "resource_id": proj_name, "resource_name": proj_name,
                            "resource_type": "CodeBuild_Project",
                            "reason": f"Last build was {days} days ago", "estimated_monthly_savings": 0,
                        })
    except Exception:
        pass
    return findings


def get_idle_cognito_pools(cognito):
    """Find Cognito User Pools with no recent activity."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    try:
        pools = cognito.list_user_pools(MaxResults=60).get("UserPools", [])
        for pool in pools:
            pool_id = pool["Id"]
            pool_name = pool.get("Name", pool_id)
            last_modified = pool.get("LastModifiedDate")
            if last_modified and last_modified.replace(tzinfo=timezone.utc) < threshold:
                days_idle = (now - last_modified.replace(tzinfo=timezone.utc)).days
                findings.append({
                    "resource_id": pool_id, "resource_name": pool_name, "resource_type": "Cognito_UserPool",
                    "reason": f"User pool not modified in {days_idle} days (verify sign-in activity)",
                    "estimated_monthly_savings": 0,
                })
    except Exception:
        pass
    return findings


def get_idle_cloudwatch_alarms(cloudwatch):
    """Find CloudWatch alarms in INSUFFICIENT_DATA state."""
    findings = []
    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for page in paginator.paginate(StateValue="INSUFFICIENT_DATA"):
            for alarm in page.get("MetricAlarms", []):
                alarm_name = alarm["AlarmName"]
                findings.append({
                    "resource_id": alarm.get("AlarmArn", alarm_name), "resource_name": alarm_name,
                    "resource_type": "CloudWatch_Alarm",
                    "reason": "Alarm in INSUFFICIENT_DATA state (resource may be deleted)",
                    "estimated_monthly_savings": 0.10,
                })
    except Exception:
        pass
    return findings


def get_idle_elasticbeanstalk_envs(eb, cloudwatch):
    """Find Elastic Beanstalk environments with no requests."""
    findings = []
    now = datetime.now(timezone.utc)
    try:
        envs = eb.describe_environments(IncludeDeleted=False).get("Environments", [])
        for env in envs:
            env_name = env["EnvironmentName"]
            env_id = env["EnvironmentId"]
            metrics = cloudwatch.get_metric_statistics(
                Namespace="AWS/ElasticBeanstalk", MetricName="RequestCount",
                Dimensions=[{"Name": "EnvironmentName", "Value": env_name}],
                StartTime=now - timedelta(days=7), EndTime=now, Period=604800, Statistics=["Sum"],
            )
            datapoints = metrics.get("Datapoints", [])
            if not datapoints or all(dp["Sum"] == 0 for dp in datapoints):
                findings.append({
                    "resource_id": env_id, "resource_name": env_name,
                    "resource_type": "ElasticBeanstalk_Env",
                    "reason": "Zero requests in last 7 days", "estimated_monthly_savings": None,
                })
    except Exception:
        pass
    return findings


def get_idle_mediaconvert_queues(mediaconvert):
    """Find MediaConvert queues with no recent jobs."""
    findings = []
    try:
        queues = mediaconvert.list_queues().get("Queues", [])
        for queue in queues:
            queue_name = queue.get("Name", "")
            if queue_name == "Default":
                continue
            status = queue.get("Status", "")
            if status == "PAUSED":
                findings.append({
                    "resource_id": queue.get("Arn", queue_name), "resource_name": queue_name,
                    "resource_type": "MediaConvert_Queue",
                    "reason": "Queue is paused", "estimated_monthly_savings": 0,
                })
    except Exception:
        pass
    return findings


def get_idle_athena_workgroups(athena, cloudwatch):
    """Find Athena workgroups with no queries."""
    findings = []
    try:
        workgroups = athena.list_work_groups().get("WorkGroups", [])
        for wg in workgroups:
            wg_name = wg["Name"]
            if wg_name == "primary":
                continue
            queries = athena.list_query_executions(WorkGroup=wg_name, MaxResults=1).get("QueryExecutionIds", [])
            if not queries:
                findings.append({
                    "resource_id": wg_name, "resource_name": wg_name, "resource_type": "Athena_Workgroup",
                    "reason": "No queries ever executed in this workgroup",
                    "estimated_monthly_savings": 0,
                })
    except Exception:
        pass
    return findings


def get_idle_medialive_channels(medialive):
    """Find MediaLive channels that are running but potentially unused."""
    findings = []
    try:
        channels = medialive.list_channels().get("Channels", [])
        for channel in channels:
            channel_id = channel["Id"]
            channel_name = channel.get("Name", channel_id)
            state = channel.get("State", "")
            channel_class = channel.get("ChannelClass", "SINGLE_PIPELINE")
            if state == "IDLE":
                findings.append({
                    "resource_id": channel_id, "resource_name": channel_name,
                    "resource_type": "MediaLive_Channel",
                    "reason": f"Channel in IDLE state ({channel_class})",
                    "estimated_monthly_savings": 0,
                })
            elif state == "RUNNING":
                est_cost = 4380.00 if channel_class == "STANDARD" else 2190.00
                findings.append({
                    "resource_id": channel_id, "resource_name": channel_name,
                    "resource_type": "MediaLive_Channel",
                    "reason": f"Channel RUNNING ({channel_class}) — verify if actively streaming",
                    "estimated_monthly_savings": est_cost,
                })
    except Exception:
        pass
    return findings


def get_idle_workspaces(workspaces):
    """Find WorkSpaces that haven't been used recently."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=30)
    try:
        paginator = workspaces.get_paginator("describe_workspaces")
        workspace_ids = []
        workspace_map = {}
        for page in paginator.paginate():
            for ws in page.get("Workspaces", []):
                ws_id = ws["WorkspaceId"]
                workspace_ids.append(ws_id)
                workspace_map[ws_id] = {
                    "name": ws.get("UserName", ws_id),
                    "running_mode": ws.get("WorkspaceProperties", {}).get("RunningMode", "ALWAYS_ON"),
                }
        for i in range(0, len(workspace_ids), 25):
            batch = workspace_ids[i:i+25]
            connections = workspaces.describe_workspaces_connection_status(
                WorkspaceIds=batch
            ).get("WorkspacesConnectionStatus", [])
            for conn in connections:
                ws_id = conn["WorkspaceId"]
                last_known = conn.get("LastKnownUserConnectionTimestamp")
                ws_info = workspace_map.get(ws_id, {})
                running_mode = ws_info.get("running_mode", "ALWAYS_ON")
                est_cost = 50.00 if running_mode == "ALWAYS_ON" else 0
                if last_known and last_known < threshold:
                    days_idle = (now - last_known.replace(tzinfo=timezone.utc)).days
                    findings.append({
                        "resource_id": ws_id, "resource_name": ws_info.get("name", ws_id),
                        "resource_type": "WorkSpaces",
                        "reason": f"No user connection in {days_idle} days ({running_mode})",
                        "estimated_monthly_savings": est_cost,
                    })
                elif not last_known:
                    findings.append({
                        "resource_id": ws_id, "resource_name": ws_info.get("name", ws_id),
                        "resource_type": "WorkSpaces",
                        "reason": f"WorkSpace has never been connected to ({running_mode})",
                        "estimated_monthly_savings": est_cost,
                    })
    except Exception:
        pass
    return findings
