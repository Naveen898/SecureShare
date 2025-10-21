# SecureShare – Dev, Test, and Deploy

This repo contains a FastAPI backend and a React (Vite) frontend. It includes Docker images, Jenkins CI/CD, and Terraform to deploy to AWS (EC2 + ALB + RDS + ECR + CloudWatch).

## Quick start (local)

- Backend (Python 3.12):
  - Create venv; install: `pip install -r backend/requirements.txt`
  - Set env (optional): `JWT_SECRET`, `AWS_S3_BUCKET`, `AWS_REGION`, `FRONTEND_BASE_URL`
  - Migrate: `alembic -c backend/alembic.ini upgrade head`
  - Run: `uvicorn backend.main:app --reload --port 8000`
  - Health: `GET /api/health/health`

- Frontend:
  - `cd frontend && npm install && npm run dev`
  - Open http://localhost:5173

## Docker (compose)

- `docker compose -f devops/docker-compose.yml up -d --build`
- Frontend on http://localhost; proxies `/api` to backend

## Tests

- Pytest config at `backend/pytest.ini`
- Run: `cd backend && pytest`
- Included tests:
  - `tests/test_scan.py` – scanner behavior
  - `tests/test_auth.py` – JWT roundtrip
  - `tests/test_health.py` – health endpoint

## Jenkins CI/CD

- See `devops/Jenkinsfile`
- Builds and pushes images to ECR; deploys to EC2 over SSH

## Terraform (AWS)

- Files in `devops/terraform`
- Creates: ECR repos, CloudWatch log groups, IAM role/profile, RDS (Postgres), ALB, EC2
- Variables: region, bucket_name, db_user, db_password, jwt_secret, key_name, etc.
- Apply: `terraform init && terraform apply -var "region=ap-south-1" ...`

## Configuration

- Backend ENV:
  - `DATABASE_URL` – Use `postgresql+asyncpg://user:pass@host:5432/db`
  - `AWS_S3_BUCKET`, `AWS_REGION`
  - `JWT_SECRET`
  - `HCAPTCHA_ENABLED` (0/1), `MFA_ADMIN_ENABLED` (fallback if SecuritySettings absent)
  - Notifications: `NOTIFY_ON_DOWNLOAD`, `NOTIFY_OWNER_ON_TRANSFER`
- Frontend ENV: `VITE_HCAPTCHA_SITE_KEY` (optional)

## Admin

- Visit `/admin` (admin users only) for dashboard and security settings
- Transfers approvals at `/admin/transfers`; My requests at `/transfers`

## Notes

- If you change DB backends, re-run Alembic migrations
- For HTTPS, attach ACM to ALB and add a new listener
- Prefer Secrets Manager/SSM Parameter Store for sensitive values in prod# SecureShare

SecureShare (formerly VaultUpload) is a secure file sharing application to upload, scan, share, and manage files with expiring links, optional secrets, and JWT-protected access.

## Features

- **File Upload**: Users can upload files to the server.
- **Virus Scanning**: Uploaded files are scanned for viruses before being stored.
- **JWT Authentication**: Files are protected by JWT tokens, ensuring only authorized users can access them.
- **Expiry Management**: Files can be set to expire after a specified duration, with automatic deletion.
- **Secure Sharing**: Users can share files via secure links that require a valid JWT token for access.

## Project Structure

```
SecureShare/
├── backend/                  # Backend application
│   ├── main.py               # Entry point of the backend app
│   ├── routes/               # API endpoints
│   ├── services/             # Core business logic
│   ├── utils/                # Helper utilities
│   ├── config/               # Configurations
│   ├── tests/                # Unit & integration tests
│   ├── requirements.txt      # Python dependencies
│   ├── Dockerfile            # Backend container image
│   └── gunicorn.conf.py      # Production server tuning
├── frontend/                 # Frontend application
│   ├── package.json          # Frontend dependencies
│   ├── vite.config.js        # Vite config
│   ├── src/                  # Source files
│   ├── public/               # Static assets
│   └── Dockerfile            # Frontend container image
├── devops/                   # DevOps configurations
│   ├── docker-compose.yml     # Local Dev setup
│   ├── k8s/                  # Kubernetes manifests
│   ├── terraform/            # Infrastructure as Code
│   └── ansible/              # Configuration management (optional)
├── .gitignore                # Files to ignore in version control
├── README.md                 # Project documentation
└── LICENSE                   # License file
```

## Getting Started

### Prerequisites

- Python 3.x
- Node.js and npm (for frontend)
- Docker (for containerization)
- Kubernetes (for deployment)

### Installation

1. Clone the repository:
   ```
  git clone https://github.com/yourusername/SecureShare.git
  cd SecureShare
   ```

2. Set up the backend:
   - Navigate to the `backend` directory.
   - Install dependencies:
     ```
     pip install -r requirements.txt
     ```

3. Set up the frontend:
   - Navigate to the `frontend` directory.
   - Install dependencies:
     ```
     npm install
     ```

### Running the Application

- To run the backend:
  ```
  cd backend
  python main.py
  ```

- To run the frontend:
  ```
  cd frontend
  npm run dev
  ```

### API Documentation

Refer to the API documentation in the `backend/routes` directory for detailed information on available endpoints.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.