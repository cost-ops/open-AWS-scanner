# Development Log — Open AWS Scanner

## Project Stats
- **Started:** July 2026
- **Estimated effort (with AI):** 8-12 hours
- **Equivalent manual effort:** 2-3 weeks solo developer

---

## Changelog

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
| 17 scanners (not 55) | Keep core package lean, upsell to full platform |
| Shared code with CostOps | One codebase, `sync-scanner-pkg.sh` keeps them aligned |
| Sigstore signing | Supply chain security, no GPG key management |
| MIT license | Maximum adoption, no legal barriers |
