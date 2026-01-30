<br /><br />

<p align="center">
<a href="https://plane.so">
  <img src="https://media.docs.plane.so/logo/plane_github_readme.png" alt="Plane Logo" width="400">
</a>
</p>
<p align="center"><b>Modern project management for all teams</b></p>

<p align="center">
<a href="https://discord.com/invite/A92xrEGCge">
<img alt="Discord online members" src="https://img.shields.io/discord/1031547764020084846?color=5865F2&label=Discord&style=for-the-badge" />
</a>
<img alt="Commit activity per month" src="https://img.shields.io/github/commit-activity/m/makeplane/plane?style=for-the-badge" />
</p>

<p align="center">
    <a href="https://plane.so/"><b>Website</b></a> •
    <a href="https://github.com/makeplane/plane/releases"><b>Releases</b></a> •
    <a href="https://twitter.com/planepowers"><b>Twitter</b></a> •
    <a href="https://docs.plane.so/"><b>Documentation</b></a>
</p>

<p>
    <a href="https://app.plane.so/#gh-light-mode-only" target="_blank">
      <img
        src="https://media.docs.plane.so/GitHub-readme/github-top.webp"
        alt="Plane Screens"
        width="100%"
      />
    </a>
</p>

Meet [Plane](https://plane.so/), an open-source project management tool to track issues, run ~sprints~ cycles, and manage product roadmaps without the chaos of managing the tool itself. 🧘‍♀️

> Plane is evolving every day. Your suggestions, ideas, and reported bugs help us immensely. Do not hesitate to join in the conversation on [Discord](https://discord.com/invite/A92xrEGCge) or raise a GitHub issue. We read everything and respond to most.

## 🚀 Installation

Getting started with Plane is simple. Choose the setup that works best for you:

- **Plane Cloud**
  Sign up for a free account on [Plane Cloud](https://app.plane.so)—it's the fastest way to get up and running without worrying about infrastructure.

- **Self-host Plane**
  Prefer full control over your data and infrastructure? Install and run Plane on your own servers. Follow our detailed [deployment guides](https://developers.plane.so/self-hosting/overview) to get started.

| Installation methods | Docs link                                                                                                                                                                               |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Docker               | [![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://developers.plane.so/self-hosting/methods/docker-compose)         |
| Kubernetes           | [![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=for-the-badge&logo=kubernetes&logoColor=white)](https://developers.plane.so/self-hosting/methods/kubernetes) |

`Instance admins` can configure instance settings with [God mode](https://developers.plane.so/self-hosting/govern/instance-admin).

## 🔒 Deploying from This Fork (Security-Hardened)

This fork includes comprehensive security fixes. Choose your deployment method below.

### Prerequisites

- Docker & Docker Compose v2+
- Git
- Domain name with DNS configured
- Minimum 2 vCPUs, 4GB RAM (8GB recommended)

---

### Method 1: Standalone Docker Compose (Recommended)

```bash
# 1. Clone and checkout
git clone https://github.com/egeorcun/plane.git
cd plane
git checkout preview

# 2. Run the setup script (auto-generates secure passwords)
./setup-env.sh

# 3. Build and deploy
docker compose -f docker-compose.production.yml up -d --build

# 4. Check status
docker compose -f docker-compose.production.yml ps
docker compose -f docker-compose.production.yml logs -f
```

The setup script will:
- Generate a secure 64-character SECRET_KEY
- Generate strong passwords for PostgreSQL, RabbitMQ, and MinIO
- Auto-detect CPU cores for optimal worker configuration
- Only ask for your domain name (everything else has smart defaults)

---

### Method 2: Coolify Deployment (Zero Config)

Coolify automatically generates all passwords and credentials. You just need to:

1. **Add Application in Coolify**
   - Source: Git Repository
   - Repository: `https://github.com/egeorcun/plane.git`
   - Branch: `preview`
   - Build Pack: **Docker Compose**
   - Docker Compose File: **`docker-compose.production.yml`**

2. **That's it!** Deploy directly.

   Coolify auto-generates these `SERVICE_*` variables:
   | Coolify Variable | Used For |
   |------------------|----------|
   | `SERVICE_PASSWORD_64_SECRET` | Django SECRET_KEY |
   | `SERVICE_USER_POSTGRES` | PostgreSQL username |
   | `SERVICE_PASSWORD_POSTGRES` | PostgreSQL password |
   | `SERVICE_USER_RABBITMQ` | RabbitMQ username |
   | `SERVICE_PASSWORD_RABBITMQ` | RabbitMQ password |
   | `SERVICE_USER_MINIO` | MinIO access key |
   | `SERVICE_PASSWORD_MINIO` | MinIO secret key |
   | `SERVICE_FQDN_PLANE` | Your domain (auto from Coolify) |
   | `SERVICE_URL_PLANE` | Full URL with https:// |

3. **Optional overrides** (only if needed):
   ```bash
   # Only set these if you want custom values
   DEBUG=0
   GUNICORN_WORKERS=4
   FILE_SIZE_LIMIT=10485760
   ```

---

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret (50+ chars) | `openssl rand -base64 50` |
| `ALLOWED_HOSTS` | Your domain(s) | `plane.example.com` |
| `CORS_ALLOWED_ORIGINS` | Frontend URL | `https://plane.example.com` |
| `DEBUG` | Must be `0` | `0` |
| `POSTGRES_PASSWORD` | DB password | Strong random string |
| `RABBITMQ_PASSWORD` | MQ password | Strong random string |
| `AWS_ACCESS_KEY_ID` | MinIO access key | Random hex string |
| `AWS_SECRET_ACCESS_KEY` | MinIO secret key | Strong random string |

---

### Production Checklist

- [ ] `SECRET_KEY` is set (50+ characters, unique)
- [ ] `ALLOWED_HOSTS` contains only your specific domain(s)
- [ ] `DEBUG=0`
- [ ] `CORS_ALLOWED_ORIGINS` matches your frontend URL
- [ ] All passwords are strong and unique
- [ ] SSL/TLS is configured (via Coolify or reverse proxy)
- [ ] Database backups are configured
- [ ] Firewall only exposes ports 80/443

---

### Security Features in This Fork

| Category | Fix |
|----------|-----|
| Authentication | CSRF protection, session fixation prevention |
| Input Validation | SSRF protection (webhooks, link crawler) |
| Authorization | IDOR vulnerabilities fixed |
| Rate Limiting | All endpoints protected |
| Headers | HSTS, X-Frame-Options, CSP |
| Logging | Sensitive data masking |
| OAuth | Timing attack prevention, token expiration fix |

## 🌟 Features

- **Work Items**
  Efficiently create and manage tasks with a robust rich text editor that supports file uploads. Enhance organization and tracking by adding sub-properties and referencing related issues.

- **Cycles**
  Maintain your team’s momentum with Cycles. Track progress effortlessly using burn-down charts and other insightful tools.

- **Modules**
  Simplify complex projects by dividing them into smaller, manageable modules.

- **Views**
  Customize your workflow by creating filters to display only the most relevant issues. Save and share these views with ease.

- **Pages**
  Capture and organize ideas using Plane Pages, complete with AI capabilities and a rich text editor. Format text, insert images, add hyperlinks, or convert your notes into actionable items.

- **Analytics**
  Access real-time insights across all your Plane data. Visualize trends, remove blockers, and keep your projects moving forward.

## 🛠️ Local development

See [CONTRIBUTING](./CONTRIBUTING.md)

## ⚙️ Built with

[![React Router](https://img.shields.io/badge/-React%20Router-CA4245?logo=react-router&style=for-the-badge&logoColor=white)](https://reactrouter.com/)
[![Django](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=green)](https://www.djangoproject.com/)
[![Node JS](https://img.shields.io/badge/node.js-339933?style=for-the-badge&logo=Node.js&logoColor=white)](https://nodejs.org/en)

## 📸 Screenshots

  <p>
    <a href="https://plane.so" target="_blank">
      <img
        src="https://media.docs.plane.so/GitHub-readme/github-work-items.webp"
        alt="Plane Views"
        width="100%"
      />
    </a>
  </p>
  <p>
    <a href="https://plane.so" target="_blank">
      <img
        src="https://media.docs.plane.so/GitHub-readme/github-cycles.webp"
        width="100%"
      />
    </a>
  </p>
  <p>
    <a href="https://plane.so" target="_blank">
      <img
        src="https://media.docs.plane.so/GitHub-readme/github-modules.webp"
        alt="Plane Cycles and Modules"
        width="100%"
      />
    </a>
  </p>
  <p>
    <a href="https://plane.so" target="_blank">
      <img
        src="https://media.docs.plane.so/GitHub-readme/github-views.webp"
        alt="Plane Analytics"
        width="100%"
      />
    </a>
  </p>
   <p>
    <a href="https://plane.so" target="_blank">
      <img
        src="https://media.docs.plane.so/GitHub-readme/github-analytics.webp"
        alt="Plane Pages"
        width="100%"
      />
    </a>
  </p>
</p>

## 📝 Documentation

Explore Plane's [product documentation](https://docs.plane.so/) and [developer documentation](https://developers.plane.so/) to learn about features, setup, and usage.

## ❤️ Community

Join the Plane community on [GitHub Discussions](https://github.com/orgs/makeplane/discussions) and our [Discord server](https://discord.com/invite/A92xrEGCge). We follow a [Code of conduct](https://github.com/makeplane/plane/blob/master/CODE_OF_CONDUCT.md) in all our community channels.

Feel free to ask questions, report bugs, participate in discussions, share ideas, request features, or showcase your projects. We’d love to hear from you!

## 🛡️ Security

If you discover a security vulnerability in Plane, please report it responsibly instead of opening a public issue. We take all legitimate reports seriously and will investigate them promptly. See [Security policy](https://github.com/makeplane/plane/blob/master/SECURITY.md) for more info.

To disclose any security issues, please email us at security@plane.so.

## 🤝 Contributing

There are many ways you can contribute to Plane:

- Report [bugs](https://github.com/makeplane/plane/issues/new?assignees=srinivaspendem%2Cpushya22&labels=%F0%9F%90%9Bbug&projects=&template=--bug-report.yaml&title=%5Bbug%5D%3A+) or submit [feature requests](https://github.com/makeplane/plane/issues/new?assignees=srinivaspendem%2Cpushya22&labels=%E2%9C%A8feature&projects=&template=--feature-request.yaml&title=%5Bfeature%5D%3A+).
- Review the [documentation](https://docs.plane.so/) and submit [pull requests](https://github.com/makeplane/docs) to improve it—whether it's fixing typos or adding new content.
- Talk or write about Plane or any other ecosystem integration and [let us know](https://discord.com/invite/A92xrEGCge)!
- Show your support by upvoting [popular feature requests](https://github.com/makeplane/plane/issues).

Please read [CONTRIBUTING.md](https://github.com/makeplane/plane/blob/master/CONTRIBUTING.md) for details on the process for submitting pull requests to us.

### Repo activity

![Plane Repo Activity](https://repobeats.axiom.co/api/embed/2523c6ed2f77c082b7908c33e2ab208981d76c39.svg "Repobeats analytics image")

### We couldn't have done this without you.

<a href="https://github.com/makeplane/plane/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=makeplane/plane" />
</a>

## License

This project is licensed under the [GNU Affero General Public License v3.0](https://github.com/makeplane/plane/blob/master/LICENSE.txt).
