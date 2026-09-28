# Setup guide

Takes about 45 minutes the first time. Commands are shown for Windows PowerShell; they work the same on Mac/Linux.

---

## Part 0 - Install the tools (one time)

| Tool | Get it from | Check it works |
|---|---|---|
| Git | git-scm.com | `git --version` |
| Python 3.12 | python.org (tick **Add to PATH**) | `py --version` |
| AWS CLI v2 | aws.amazon.com/cli | `aws --version` |
| Terraform | developer.hashicorp.com/terraform/install (or `winget install Hashicorp.Terraform`) | `terraform -version` |
| Docker Desktop *(optional, for local builds)* | docker.com | `docker --version` |

Close and reopen your terminal after installing so the new commands are found.

---

## Part 1 - AWS account access for Terraform

1. Sign in to the AWS console as the root user and **turn on MFA** for root (Security credentials > MFA).
2. Go to **IAM > Users > Create user** and name it `terraform-admin`.
3. Attach the policy **AdministratorAccess**. Terraform creates IAM roles, so it needs broad rights. This user is only for you, on your machine.
4. Open the user > **Security credentials > Create access key > Command Line Interface (CLI)**. Copy both keys.
5. In your terminal:
   ```powershell
   aws configure
   # AWS Access Key ID:     <paste>
   # AWS Secret Access Key: <paste>
   # Default region name:   us-east-1
   # Default output format: json
   aws sts get-caller-identity    # should print your account number
   ```

> 🔒 Never put these keys in the repository or in GitHub. GitHub uses OIDC instead and never sees any keys. Delete the access key when you finish the project.

---

## Part 2 - Put the code on GitHub

Using Git (or PyCharm's Git features) avoids the folder-flattening problems of drag-and-drop uploads, especially for the hidden `.github` folder.

1. On GitHub, create a new **public** repository named **`aws-appsec-pipeline`**. Leave it empty (no README).
2. In a terminal inside the unzipped project folder:
   ```powershell
   git init
   git add .
   git commit -m "Initial commit: AWS AppSec pipeline"
   git branch -M main
   git remote add origin https://github.com/eguidey/aws-pipeline-2.git
   git push -u origin main
   ```
3. Open the **Actions** tab. The security stages (tests, Bandit, pip-audit, Gitleaks, Checkov, image build + Trivy) run and should all pass. **Push/deploy are skipped** for now, which is expected because AWS isn't set up yet.

---

## Part 3 - Create the AWS infrastructure

The Terraform is split into reusable modules (`infra/modules/`) composed by `infra/main.tf`. Each environment has its own settings file and its own state file under `infra/environments/`.

1. Find your public IP (so only you can reach the API) and your GitHub IDs (repositories created after July 15, 2026 use GitHub's "immutable" OIDC identity, which includes them):
   ```powershell
   (Invoke-WebRequest https://checkip.amazonaws.com).Content
   Invoke-RestMethod https://api.github.com/repos/eguidey/aws-pipeline-2 | Select-Object id, @{n="owner_id";e={$_.owner.id}}
   ```
2. Create the bootstrap stack (one time): the encrypted, versioned S3 bucket for Terraform state, the account's GitHub OIDC provider, and the two roles GitHub Actions uses to run Terraform. These live outside the app stack so `terraform destroy` can never delete the state or cut the pipeline off from AWS.
   ```powershell
   cd infra\bootstrap
   copy bootstrap.tfvars.example bootstrap.tfvars
   notepad bootstrap.tfvars                  # your repo name + the two IDs from step 1
   terraform init
   terraform apply -var-file=bootstrap.tfvars    # type "yes" - note the outputs
   cd ..
   ```
   > **Same AWS account as the original `aws-appsec-pipeline`?** Keep `create_github_oidc_provider = false` in `bootstrap.tfvars` (the default in the example); the original owns the account's one GitHub OIDC provider. See [Running alongside the original deployment](#running-alongside-the-original-deployment).
3. Create your production settings (both files are git-ignored):
   ```powershell
   copy environments\prod.tfvars.example environments\prod.tfvars
   copy environments\prod.backend.hcl.example environments\prod.backend.hcl
   notepad environments\prod.tfvars          # email, GitHub IDs, your IP
   notepad environments\prod.backend.hcl     # replace ACCOUNT_ID with your 12-digit account ID
   ```
4. Create everything:
   ```powershell
   terraform init -backend-config=environments\prod.backend.hcl
   terraform plan  -var-file=environments\prod.tfvars    # about 90 resources to add
   terraform apply -var-file=environments\prod.tfvars    # type "yes"
   ```
   If you see *"MaxNumberOfConfigurationRecorders"*, add `enable_aws_config = false`.

   Terraform now refuses values the policy doesn't allow, before anything is created: a region missing from `policy/rules.json`, an environment other than `prod`/`dev`, or a CPU/memory pair Fargate can't run (e.g. `task_cpu = 256` needs `task_memory` of 512, 1024 or 2048).
5. **Check your email** and click **Confirm subscription** in the message from AWS Notifications. Without this, alerts won't arrive.

---

## Part 4 - Connect GitHub to AWS

1. Show the values you need:
   ```powershell
   terraform output
   ```
2. In your GitHub repository: **Settings > Secrets and variables > Actions > Variables tab > New repository variable**. Add these six. They are **variables**, not secrets, because none of them are sensitive:

   | Name | Value from `terraform output` |
   |---|---|
   | `AWS_REGION` | `aws_region` |
   | `AWS_DEPLOY_ROLE_ARN` | `github_deploy_role_arn` |
   | `ECR_REPOSITORY` | `ecr_repository_name` |
   | `ECS_CLUSTER` | `ecs_cluster_name` |
   | `ECS_SERVICE` | `ecs_service_name` |
   | `ECS_TASK_FAMILY` | `ecs_task_family` |

3. *(Optional, recommended)* **Settings > Environments > New environment** named `production`. Tick **Required reviewers** and add yourself, so every deployment waits for your approval.

4. **Let GitHub Actions run Terraform too** (the `Infrastructure` workflow, `.github/workflows/infra.yml`):

   | Kind | Name | Value |
   |---|---|---|
   | Variable | `TF_PLAN_ROLE_ARN` | `terraform_plan_role_arn` from the **bootstrap** outputs |
   | Variable | `TF_APPLY_ROLE_ARN` | `terraform_apply_role_arn` from the **bootstrap** outputs |
   | Variable | `TF_STATE_BUCKET` | `state_bucket` from the **bootstrap** outputs |
   | **Secret** | `TFVARS_PROD` | The full contents of `infra\environments\prod.tfvars` |

   `TFVARS_PROD` is a **secret** (Secrets tab), because it holds your email and IP. Terraform marks those values sensitive, so they never appear in the public Actions logs.

   Then **Settings > Environments > New environment** named **`infrastructure`**:
   - Tick **Required reviewers** and add yourself. The apply role has admin rights, so a human approves every apply.
   - Under **Deployment branches and tags**, choose **Selected branches** and add `main`.

   What happens from now on:
   - A **pull request** touching `infra/`, `policy/`, `detections/` or `lambda/` runs `terraform plan` with the read-only role, then the **policy gate**. The PR fails if the plan breaks a guardrail.
   - A **merge to `main`** plans again, runs the gate, waits for your approval, then applies exactly the plan that passed.
   - Whenever you change `prod.tfvars` locally, update the `TFVARS_PROD` secret too.

---

## Part 5 - First deployment

1. **Actions > AppSec Pipeline > Run workflow > Run workflow** (on `main`).
2. After the security gates pass, the image is pushed to ECR and the **Deploy** job starts. Approve it if you set up the environment reviewer.
3. The deploy job registers a new task definition, starts one Fargate task and waits for it to be healthy (about 2-4 minutes). The smoke test prints the task's public IP.

   The smoke test shows a warning if you limited `allowed_ingress_cidrs` to your own IP, because GitHub's servers can't reach it. That's expected; test from your own computer instead.

4. Test it from your computer (use the IP from the deploy log):
   ```powershell
   curl http://<PUBLIC-IP>:8000/health
   curl http://<PUBLIC-IP>:8000/api/items
   ```

---

## Part 6 - Test the detections

1. Run the attack simulator against **your own** deployment:
   ```powershell
   py scripts/simulate_attacks.py http://<PUBLIC-IP>:8000
   ```
2. Within about 5 minutes you should get alarm emails for **brute_force**, **auth_failure_spike**, **injection_attempt** and **rate_limited**.
3. Investigate like an analyst:
   - **CloudWatch > Alarms**: see which fired and when.
   - **CloudWatch > Logs Insights > Saved queries** (`aws-pipeline-2/...`): run *top_source_ips* and *injection_attempts*.
   - **CloudWatch > Log groups > /ecs/aws-pipeline-2**: the raw JSON events.
4. Take screenshots of the pipeline run, an alarm email, and a Logs Insights result. They're useful for your README, a blog post, or an interview.

**Try the real login:** the password is in Secrets Manager (`aws-pipeline-2/demo-password`), where you can view it in the console. POST it to `/api/login` with username `analyst` to see an `auth_success` event.

---

## Part 7 - Tear down (don't skip!)

When you're done for the day, stop paying for the running task:

```powershell
aws ecs update-service --cluster aws-pipeline-2 --service aws-pipeline-2 --desired-count 0
```

When you're done with the project, remove **everything** (from the `infra` folder):

```powershell
cd infra
terraform destroy -var-file=environments\prod.tfvars    # type "yes"
```

Then delete the `terraform-admin` access key in IAM.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Deploy fails: *Not authorized to perform sts:AssumeRoleWithWebIdentity* | `github_repository`, `github_owner_id` and `github_repository_id` in `environments\prod.tfvars` must match your repo. Compare with the `trusted_github_subjects` Terraform output, fix, and `terraform apply -var-file=environments\prod.tfvars` again. |
| Deploy job skipped | The `AWS_DEPLOY_ROLE_ARN` variable is missing, or the run wasn't on `main`. |
| Deploy stops at **Policy gate** | The log lists each violation (e.g. a container made writable, or an image not pinned by digest). Fix the Terraform or `policy/rules.json` through a PR. |
| `Infrastructure` workflow jobs skipped | `TF_PLAN_ROLE_ARN` / `TF_APPLY_ROLE_ARN` aren't set, or the PR comes from a fork (forks never get AWS credentials). |
| `Infrastructure` workflow: *Not authorized to perform sts:AssumeRoleWithWebIdentity* | Compare the bootstrap output `trusted_terraform_subjects` with your repo and IDs; the apply job must use the `infrastructure` environment. |
| `Invalid value for variable` on region / task size | The value breaks `policy/rules.json`. Pick an allowed value, or change the policy file through review. |
| `AccessDenied ... explicit deny` in another region | Intended: both CI roles and the deploy role are locked to `allowed_regions`. |
| Task keeps stopping | Check **CloudWatch > Log groups > /ecs/aws-pipeline-2** and **ECS > Cluster > Service > Events**. The circuit breaker rolls back failed releases. |
| Trivy fails on a new CVE | Usually fixed by rebuilding (the image upgrades OS packages) or by bumping the version Dependabot suggests. |
| No alarm emails | Confirm the SNS subscription email (Part 3, step 5) and check spam. |
| `terraform destroy` fails on the ECR repository | Run it again; `force_delete` removes the images. |
| `EntityAlreadyExists ... token.actions.githubusercontent.com` in the bootstrap | The provider already exists (normally from the original deployment). Set `create_github_oidc_provider = false` in `bootstrap.tfvars` and apply again. |
| Pipeline fails at **Terraform format check** or **validate** | The log shows the exact file and line; fix it (or run `terraform fmt -recursive infra`) and push again. |

---

## Running alongside the original deployment

This repository (`aws-pipeline-2`) can share an AWS account with the original `aws-appsec-pipeline`. They stay separate because:

| Shared thing | How the two are kept apart |
|---|---|
| Resource names | Every name is prefixed with `project_name` (`aws-pipeline-2` vs `appsec-api`) |
| Terraform state | Separate bucket (`aws-pipeline-2-tfstate-<account>`), separate bootstrap stack |
| Network | Separate VPC (`10.42.0.0/16` vs `10.40.0.0/16`) and its own NACL, so each responder only blocks traffic to its own API |
| Metrics & alarms | Separate CloudWatch namespace (`AppSec/aws-pipeline-2`) |
| GitHub OIDC provider (one per account) | Owned by the original; this project's bootstrap only looks it up |
| AWS Config recorder (one per region) | Owned by the original; `enable_aws_config = false` here |
| GitHub roles | Each trusts only its own repository, by name and numeric ID |

Running both roughly doubles the cost while both containers run. Scale the one you're not using to zero, e.g. the original:
`aws ecs update-service --cluster appsec-api --service appsec-api --desired-count 0`

## Retiring the original deployment

The original owns two account-wide things this project relies on. Hand them over **before** destroying it, or this project's pipelines lose their AWS login.

1. **In the original project's `infra` folder**, release the OIDC provider, then destroy:
   ```powershell
   terraform init -backend-config="environments\prod.backend.hcl"
   terraform state rm 'module.cicd_identity.aws_iam_openid_connect_provider.github[0]'
   terraform plan    -destroy -var-file="environments\prod.tfvars"   # confirm the OIDC provider is NOT listed
   terraform destroy -var-file="environments\prod.tfvars"
   ```
2. **In this project's `infra\bootstrap` folder**, adopt the provider: set `create_github_oidc_provider = true` in `bootstrap.tfvars`, then:
   ```powershell
   $acct = aws sts get-caller-identity --query Account --output text
   terraform import -var-file="bootstrap.tfvars" 'aws_iam_openid_connect_provider.github[0]' "arn:aws:iam::${acct}:oidc-provider/token.actions.githubusercontent.com"
   terraform plan  -var-file="bootstrap.tfvars"    # expect 0 to destroy
   terraform apply -var-file="bootstrap.tfvars"
   ```
3. **Turn on AWS Config here:** set `enable_aws_config = true` in `infra\environments\prod.tfvars` (and the `TFVARS_PROD` secret), then apply.
4. The original's state bucket (`appsec-api-tfstate-<account>`) is protected from deletion. Empty and delete it in the S3 console if you no longer need its history.
