# Development Log — Open AWS Scanner

## Project Stats
- **Started:** July 2026
- **Published:** PyPI (`open-aws-scanner`)
- **Version:** 0.2.1
- **Scanners:** 55 AWS resource types
- **Estimated effort (with AI):** 8-12 hours
- **Equivalent manual effort:** 2-3 weeks solo developer

---

## Changelog

### 2026-07-09
- **v0.2.0**: All 55 scanners ported from costops to open package
  - S3 inactive/stale, Redshift, OpenSearch, Neptune, DocumentDB
  - EKS, App Runner, Elastic Beanstalk, EFS, FSx
  - Kinesis, SageMaker, API Gateway, Step Functions, Glue
  - VPN, Transit Gateways, KMS, Route 53, EventBridge
  - EMR, AMIs, Lightsail, WAF, Global Accelerator
  - CodePipeline, CodeBuild, Cognito, CloudWatch Alarms
  - MediaConvert, MediaLive, Athena, WorkSpaces
- **v0.2.1**: Added `--version` / `-v` CLI flag, `/status` endpoint for admin integration
- **Published to PyPI** via GitHub Actions (Trusted Publisher + Sigstore signing)
- **Text-based index page**: `GET /` returns JSON status summary with endpoint list (removed HTML dashboard)
- costops-AWS-scanner now imports all 55 scanners from this package
- Fixed publish workflow: sigstore signing inline, upload `.sigstore.json` to release, exclude from PyPI upload
- All 56 costops tests passing with shared package

### 2026-07-08
- Initial release as open-source pip package
- CLI with commands: `init`, `scan`, `serve`
- 17 resource scanners (core subset of CostOps 55)
- SQLite by default, optional PostgreSQL
- API server mode with Swagger docs
- Role assumption support (cross-account)
- Stage mode (mock data for testing)
- Docker support
- Sigstore signing for releases
- GitHub Actions CI/CD (release workflow)
- MIT license

---

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| pip package | Easy distribution, zero infrastructure to try |
| CLI-first | DevOps/SRE users prefer terminal workflows |
| SQLite default | Zero config, works locally out of the box |
| All 55 scanners | Full parity with CostOps platform |
| Shared code with CostOps | One codebase, costops imports from this package |
| Sigstore signing | Supply chain security, no GPG key management |
| SSH commit signing | Verified commits on GitHub |
| PyPI Trusted Publisher | No API tokens, OIDC-based publish from GitHub Actions |
| MIT license | Maximum adoption, no legal barriers |
