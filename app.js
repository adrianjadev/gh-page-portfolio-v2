/* ==========================================================================
   app.js — Adrian Jade Manaday · Portfolio
   Plain JavaScript. No framework, no build step, no dependencies.
   Edit the PORTFOLIO object to update content; the rest renders it.
   ========================================================================== */
   "use strict";

   /* ---------- 1. Content ---------- */
   const PORTFOLIO = {
     githubHandle: "adrianjadev",
     githubSync: { enabled: true, maxRepos: 6 }, // live repos replace the curated list on GitHub Pages
   
     fallbackRepos: [
       { name: "gcp-security-blueprints", language: "HCL", url: "https://github.com/adrianjadev/gcp-security-blueprints",
         description: "Hub monorepo: Terraform GCP baselines, custom IAM policies, container hardening and DevSecOps CI (Checkov, Trivy, Gitleaks)." },
       { name: "gcp-terraform-infra-baseline", language: "HCL", url: "https://github.com/adrianjadev/gcp-terraform-infra-baseline",
         description: "Modular Compute, custom VPC, GCS remote state and IAP-only SSH, rebuilt from GSP345 (100/100)." },
       { name: "gcp-multi-vpc-gke-segmentation", language: "HCL", url: "https://github.com/adrianjadev/gcp-multi-vpc-gke-segmentation",
         description: "Custom-mode dev/prod VPC isolation, dual-NIC bastion and GKE with Cloud SQL Auth Proxy (GSP321)." },
       { name: "gcp-iam-least-privilege-lab", language: "Python", url: "https://github.com/adrianjadev/gcp-iam-least-privilege-lab",
         description: "Custom IAM roles and a gcloud auditor that flags Owner/Editor bindings and stale service-account keys." },
       { name: "k8s-container-hardening-lab", language: "Dockerfile", url: "https://github.com/adrianjadev/k8s-container-hardening-lab",
         description: "Distroless non-root migration with a strict Kubernetes SecurityContext and a Trivy CVE gate." },
       { name: "gcp-kms-data-protection-lab", language: "HCL", url: "https://github.com/adrianjadev/gcp-kms-data-protection-lab",
         description: "Cloud KMS key rings with 90-day rotation and CMEK-enforced private Cloud Storage buckets." }
     ],
   
     projects: [
       {
         id: "gsp345-terraform-baseline",
         category: "Terraform & IaC",
         status: "Verified lab · 100/100",
         verified: true,
         title: "GCP infrastructure-as-code security baseline",
         repoUrl: "https://github.com/adrianjadev/gcp-terraform-infra-baseline",
         summary: "Reusable Terraform modules for custom VPCs, hardened Compute Engine, versioned GCS remote state and IAP-only SSH, rebuilt from the GSP345 skill badge.",
         problem: "Manual console provisioning produces undocumented firewall exceptions, unversioned drift and inconsistent controls across environments.",
         controls: [
           "Structured compute, VPC and storage into composable Terraform modules with strict input validation.",
           "Isolated state in a versioned Cloud Storage backend, with .gitignore rules that keep state and tfvars out of Git.",
           "GitHub Actions runs terraform fmt -check, terraform validate and Checkov CIS GCP checks on every pull request."
         ],
         verification: "Scored 100/100 on Challenge Lab GSP345; confirmed a zero-drift terraform plan and passing Checkov baseline scans.",
         stack: ["Terraform", "GCP VPC", "Cloud Storage", "Compute Engine", "Checkov", "GitHub Actions"],
         diagram: "terraform-ci",
         artifact: {
           file: "iap-firewall.tf",
           code: `terraform {
     required_version = ">= 1.6.0"
   
     backend "gcs" {
       bucket = "tf-state-security-baseline"
       prefix = "terraform/state"
     }
   }
   
   resource "google_compute_firewall" "allow_iap_ssh" {
     name          = "allow-ssh-via-iap-only"
     network       = google_compute_network.custom_vpc.id
     direction     = "INGRESS"
     priority      = 1000
     source_ranges = ["35.235.240.0/20"] # Google Identity-Aware Proxy
   
     allow {
       protocol = "tcp"
       ports    = ["22"]
     }
   
     log_config {
       metadata = "INCLUDE_ALL_METADATA"
     }
   }`
         }
       },
       {
         id: "gsp321-multi-vpc-gke",
         category: "Networking",
         status: "Verified lab · GSP321",
         verified: true,
         title: "Multi-VPC segmentation and GKE workload isolation",
         repoUrl: "https://github.com/adrianjadev/gcp-multi-vpc-gke-segmentation",
         summary: "Custom-mode dev and prod VPCs across four /20 subnets, a dual-NIC management bastion, GKE backed by Cloud SQL Auth Proxy, and role-scoped monitoring.",
         problem: "Auto-mode VPCs flatten trust boundaries, letting a compromised workload reach management planes or production databases.",
         controls: [
           "Provisioned custom-mode VPCs (griffin-dev-vpc, griffin-prod-vpc) separating application and management tiers.",
           "Deployed a dual-NIC bastion restricted to management subnets so application nodes never expose public SSH.",
           "Connected GKE pods to Cloud SQL through the Auth Proxy sidecar and scoped observability to roles/monitoring.editor."
         ],
         verification: "Completed Challenge Lab GSP321; validated subnet isolation, uptime alerts and scoped IAM bindings.",
         stack: ["GCP VPC", "GKE", "Dual-NIC bastion", "Cloud SQL Proxy", "Cloud IAM"],
         diagram: "multi-vpc",
         artifact: {
           file: "vpc-segmentation.tf",
           code: `resource "google_compute_network" "dev_vpc" {
     name                    = "griffin-dev-vpc"
     auto_create_subnetworks = false
   }
   
   resource "google_compute_subnetwork" "dev_app" {
     name                     = "griffin-dev-wp"
     ip_cidr_range            = "192.168.16.0/20"
     network                  = google_compute_network.dev_vpc.id
     private_ip_google_access = true
   }
   
   resource "google_compute_subnetwork" "dev_mgmt" {
     name          = "griffin-dev-mgmt"
     ip_cidr_range = "192.168.32.0/20"
     network       = google_compute_network.dev_vpc.id
   }`
         }
       },
       {
         id: "iam-least-privilege-auditor",
         category: "IAM & Zero Trust",
         status: "Blueprint",
         verified: false,
         title: "Least-privilege IAM and custom-role policy auditor",
         repoUrl: "https://github.com/adrianjadev/gcp-iam-least-privilege-lab",
         summary: "Declarative custom IAM roles plus a Python/gcloud auditor that flags primitive Owner/Editor grants, stale user-managed keys and unconditioned bindings.",
         problem: "Broad primitive roles and static JSON keys widen the blast radius of a credential compromise and break least-privilege compliance.",
         controls: [
           "Version-controlled custom read-only role definitions in YAML replacing basic Viewer/Editor grants.",
           "Audit check that flags primitive roles and user-managed service-account keys older than 90 days.",
           "Documented SSO federation and time-bound IAM Conditions for break-glass elevation."
         ],
         verification: "CI exits non-zero when sample policies introduce roles/owner or static-key drift.",
         stack: ["GCP IAM", "SSO", "IAM Conditions", "Python", "gcloud CLI"],
         diagram: "iam-flow",
         artifact: {
           file: "auditor-role.yaml",
           code: `title: "Cloud Security Posture Auditor"
   description: "Minimal read-only role replacing primitive Viewer/Editor bindings."
   stage: "GA"
   includedPermissions:
     - compute.firewalls.list
     - compute.networks.list
     - iam.roles.get
     - iam.serviceAccounts.list
     - iam.serviceAccountKeys.list
     - resourcemanager.projects.getIamPolicy
     - cloudkms.cryptoKeys.list`
         }
       },
       {
         id: "distroless-k8s-hardening",
         category: "Containers",
         status: "Blueprint",
         verified: false,
         title: "Distroless container hardening with a Trivy CI gate",
         repoUrl: "https://github.com/adrianjadev/k8s-container-hardening-lab",
         summary: "Before-and-after study migrating a root-user image to a multi-stage distroless build with a strict Pod SecurityContext and Trivy CVE gating.",
         problem: "Default base images ship package managers, shells and UID 0 execution, inflating attack surface and post-exploit impact.",
         controls: [
           "Multi-stage Dockerfile targeting distroless static non-root (UID 65532) with no shell binaries.",
           "readOnlyRootFilesystem, allowPrivilegeEscalation: false and capabilities drop ALL enforced in manifests.",
           "GitHub Actions Trivy gate blocks merges on CRITICAL or fixable HIGH vulnerabilities."
         ],
         verification: "Measured the Trivy CVE reduction between baseline and distroless builds and verified the immutable root filesystem.",
         stack: ["Kubernetes", "Docker", "Distroless", "Trivy", "GitHub Actions"],
         diagram: "container-ci",
         artifact: {
           file: "Dockerfile.hardened",
           code: `FROM golang:1.22-alpine AS builder
   WORKDIR /src
   COPY go.mod go.sum ./
   RUN go mod download
   COPY . .
   RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app .
   
   # Zero shell, zero package manager, non-root runtime
   FROM gcr.io/distroless/static-debian12:nonroot
   USER nonroot:nonroot
   COPY --from=builder /out/app /app
   EXPOSE 8080
   ENTRYPOINT ["/app"]`
         }
       },
       {
         id: "kms-cmek-vault",
         category: "Data protection",
         status: "Blueprint",
         verified: false,
         title: "Cloud KMS key lifecycle and CMEK storage vault",
         repoUrl: "https://github.com/adrianjadev/gcp-kms-data-protection-lab",
         summary: "Terraform-provisioned KMS key rings with 90-day automatic rotation, CMEK-encrypted buckets and public-access prevention for restricted PII.",
         problem: "Sensitive data stored without customer-managed keys, rotation or bucket access guards raises compliance and leak risk.",
         controls: [
           "Symmetric KMS keys with 90-day automatic rotation and prevent_destroy lifecycle guards.",
           "CMEK encryption, uniform bucket-level access and public_access_prevention enforced on buckets.",
           "Data classification tiers (Public, Internal, Confidential, Restricted PII) mapped to encryption controls."
         ],
         verification: "Checked rotation state with gcloud kms keys versions list and confirmed unauthorized decrypt calls are denied.",
         stack: ["Cloud KMS", "CMEK", "Cloud Storage", "Terraform"],
         diagram: "kms-flow",
         artifact: {
           file: "kms-vault.tf",
           code: `resource "google_kms_crypto_key" "pii_cmek" {
     name            = "pii-vault-cmek"
     key_ring        = google_kms_key_ring.sec_ring.id
     rotation_period = "7776000s" # 90-day automatic rotation
   
     lifecycle {
       prevent_destroy = true
     }
   }
   
   resource "google_storage_bucket" "restricted_vault" {
     name                        = "\${var.project_id}-restricted-vault"
     location                    = var.region
     uniform_bucket_level_access = true
     public_access_prevention    = "enforced"
   
     encryption {
       default_kms_key_name = google_kms_crypto_key.pii_cmek.id
     }
   }`
         }
       }
     ],
   
     notes: [
       {
         id: "gsp345-terraform-hygiene",
         date: "Nov 2026",
         readTime: "3 min",
         title: "Scoring 100/100 on GSP345: Terraform modules and remote-state hygiene",
         excerpt: "Turning ad-hoc console changes into auditable modules, isolating GCS state, and gating PRs with static checks.",
         callout: "Infrastructure as code only works as a security control when state is remote, versioned, and verified automatically before apply.",
         paragraphs: [
           "Completing the Build Infrastructure with Terraform on Google Cloud challenge lab (GSP345) reinforced why repeatable modules beat manual console clicks. Every ad-hoc firewall rule or VM edit introduces drift that security teams cannot reliably audit.",
           "Structuring compute, storage and networking into clean Terraform modules, paired with a remote Cloud Storage backend, establishes a single auditable source of truth. In production, running terraform fmt, terraform validate and Checkov CIS GCP policies inside GitHub Actions catches misconfigurations before they reach cloud APIs.",
           "Repository hygiene matters just as much: keeping terraform.tfstate, sensitive .tfvars and static JSON keys out of Git with strict .gitignore rules and pre-commit secret scanning prevents credential leaks at the source."
         ]
       },
       {
         id: "iam-sso-boundaries",
         date: "Nov 2026",
         readTime: "3 min",
         title: "Least-privilege IAM and SSO trust boundaries on Google Cloud",
         excerpt: "Replacing basic Owner/Editor roles with scoped custom roles, IAM Conditions and keyless Workload Identity Federation.",
         callout: "Assume every identity can be compromised: narrow permissions by default, bind elevation to conditions, and eliminate static keys.",
         paragraphs: [
           "Studying cloud access controls, SSO federation and risk management highlights a recurring root cause behind cloud incidents: overly broad roles paired with long-lived static credentials.",
           "Enforcing least privilege on Google Cloud starts with three habits: federating human identities through SSO, replacing primitive Owner/Editor roles with minimal predefined or custom roles, and attaching IAM Conditions whenever elevated access must be time-bound.",
           "For workloads on GKE or CI runners like GitHub Actions, Workload Identity Federation removes the risk of downloading, storing and rotating JSON service-account keys altogether."
         ]
       },
       {
         id: "gsp321-multi-vpc-notes",
         date: "Nov 2026",
         readTime: "4 min",
         title: "Dual-NIC bastion isolation and GKE hardening (GSP321 notes)",
         excerpt: "Separating application and management planes across custom-mode VPCs and scoping observability to monitoring.editor.",
         callout: "Auto-mode VPCs flatten trust boundaries. Custom-mode VPCs with non-overlapping CIDRs and dedicated management planes contain lateral movement.",
         paragraphs: [
           "In the Develop Your Google Cloud Network challenge lab (GSP321), separating development (griffin-dev-vpc) and production (griffin-prod-vpc) into custom-mode VPCs with distinct /20 application and management subnets demonstrates defense-in-depth networking.",
           "Attaching a dual-NIC bastion only to the management subnets (griffin-dev-mgmt and griffin-prod-mgmt) keeps administrative SSH off the application tier. In hardened production deployments, pairing that pattern with Identity-Aware Proxy removes public SSH exposure entirely.",
           "Finally, scoping operational access to roles/monitoring.editor lets teams inspect uptime checks and alerts without inheriting compute or IAM modification rights."
         ]
       }
     ],
   
     experience: [
       {
         period: "Nov 2022 — Present",
         role: "Security Engineer, Threat Detection",
         org: "Google Operations Center",
         bullets: [
           "Threat detection – Protected users across Gmail, Chrome, Search and Ads against phishing, malware and social-engineering threats.",
           "Large-scale analysis – Analysed large datasets with SQL, MapReduce, Python and C/C++ to surface emerging threat trends and system weaknesses.",
           "Malware analysis – Ran static and dynamic analysis of executables, browser extensions and payloads in VM detonation sandboxes to trigger evasive behaviour and confirm verdicts.",
           "Campaign tracking – Operated headless crawlers with device emulation and geo-targeted anti-cloaking proxies to inspect request chains and classify evasive web campaigns.",
           "Infrastructure investigation – Correlated domains, URLs, IPs, hashes, certificates and DNS patterns to map and disrupt malicious distribution networks.",
           "Incident triage & RCA – Led investigations into high-priority abuse incidents and escalations, isolating root causes to drive systemic fixes.",
           "Detection tuning – Audited threat-scoring signals, crawler telemetry and blocklist output to cut false positives and sharpen classification."
         ]
       },
       {
         period: "Jun 2021 — Nov 2022",
         role: "Technical Support Engineer, E-Commerce",
         org: "Oracle NetSuite",
         bullets: [
           "Platform administration – Administered web stores and mobile apps on SuiteCommerce Advanced, SuiteCommerce Standard and SuiteScript APIs.",
           "Troubleshooting – Isolated root causes between core platform functions and client-side customisations.",
           "Integrations – Configured and supported CyberSource, SAML, PayPal Express and Merchant e-Solutions.",
           "Knowledge management – Ran weekly knowledge-base maintenance reviews.",
           "Recognition – Promoted from Associate to Engineer within 16 months."
         ]
       },
       {
         period: "Jan 2020 — Jun 2021",
         role: "Data Analyst",
         org: "Accenture",
         bullets: [
           "Root-cause & trend analysis – Identified root causes and trends to improve quality-assurance processes.",
           "Performance tracking – Built an internal dashboard for team performance metrics.",
           "Recognition – Top performer three consecutive months for strict SLO adherence."
         ]
       },
       {
         period: "Sep 2018 — Jun 2021",
         role: "Junior Full-Stack Engineer (Internship)",
         org: "STRIDE Consulting Inc.",
         bullets: [
           "Development & testing – Programmed, debugged and tested new applications and maintained legacy systems.",
           "Full-stack work – Built and tested integrations with Python/Django, Node.js, React, SQL, MongoDB and C++ (Qt)."
         ]
       }
     ],
   
     skills: [
       { group: "Identity & access", items: "Cloud IAM, custom roles, IAM Conditions, SSO federation, Workload Identity, zero trust" },
       { group: "Network & perimeter", items: "Custom-mode VPC, firewall policy, Identity-Aware Proxy, bastion isolation, segmentation" },
       { group: "IaC & DevSecOps", items: "Terraform, GCS remote state, GitHub Actions, Checkov, Gitleaks, gcloud CLI" },
       { group: "Workloads & data", items: "GKE hardening, distroless containers, Trivy, Cloud KMS / CMEK, Python, Bash" },
       { group: "Threat detection", items: "Malware & payload analysis, phishing investigation, DNS & infrastructure correlation, SQL" }
     ],
   
     credentials: [
       { title: "Google Cloud Cybersecurity Certificate", issuer: "Google Cloud Skills Boost", status: "In progress",
         url: "https://www.skills.google/public_profiles/a9518546-af4d-48b3-900f-64afda9d132c" },
       { title: "Ethical Hacking", issuer: "Cisco Networking Academy", status: "In progress", url: "https://www.netacad.com/" },
       { title: "Associate Cloud Engineer → Professional Cloud Security Engineer", issuer: "Google Cloud Certification", status: "Planned",
         url: "https://cloud.google.com/learn/certification/cloud-security-engineer" }
     ]
   };
   
   /* ---------- 2. Helpers ---------- */
   const $ = (sel, root = document) => root.querySelector(sel);
   const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
   const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
   const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
   const pad = (n) => String(n).padStart(2, "0");
   
   const ICON_CLOSE =
     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>';
   
   function formatMonth(iso) {
     if (!iso) return "";
     const d = new Date(iso);
     return isNaN(d) ? "" : d.toLocaleDateString("en-US", { month: "short", year: "numeric" });
   }
   
   let toastTimer;
   function toast(msg) {
     const el = $("#toast");
     el.textContent = msg;
     el.classList.add("show");
     clearTimeout(toastTimer);
     toastTimer = setTimeout(() => el.classList.remove("show"), 2000);
   }
   
   async function copy(text, msg = "Copied") {
     try {
       await navigator.clipboard.writeText(text);
       toast(msg);
     } catch {
       toast(text); // clipboard blocked: at least show the value
     }
   }
   
   /* ---------- 3. Diagrams ---------- */
   const PIPELINES = {
     "terraform-ci": [["01  Terraform", "Modular HCL"], ["02  Validate", "fmt + plan"], ["03  Checkov", "CIS GCP gate", true], ["04  GCS state", "IAP-only VPC"]],
     "container-ci": [["01  Builder", "Multi-stage Go"], ["02  Distroless", "Non-root UID"], ["03  Trivy", "Block critical CVE", true], ["04  GKE pod", "Read-only FS"]],
     "kms-flow":     [["01  Classify", "Restricted PII"], ["02  Cloud KMS", "90-day CMEK", true], ["03  Bucket", "No public access"]],
     "iam-flow":     [["01  Identity", "SSO / workload"], ["02  Policy", "Custom + conditions", true], ["03  CI audit", "0 basic roles"]]
   };
   
   function pipelineSVG(stages) {
     const W = 560, gap = 16, n = stages.length;
     const w = Math.floor((W - gap * (n - 1)) / n);
     const nodes = stages.map(([title, sub, key], i) => {
       const x = i * (w + gap);
       const link = i < n - 1 ? `<line class="d-line" x1="${x + w}" y1="40" x2="${x + w + gap}" y2="40"/>` : "";
       return `<rect class="${key ? "d-key" : "d-box"}" x="${x}" y="8" width="${w}" height="64" rx="6"/>
         <text class="d-title${key ? " d-accent" : ""}" x="${x + 12}" y="35" xml:space="preserve">${esc(title)}</text>
         <text class="d-sub" x="${x + 12}" y="55">${esc(sub)}</text>${link}`;
     }).join("");
     return `<svg viewBox="0 0 ${W} 80" role="img" aria-label="Security control pipeline">${nodes}</svg>`;
   }
   
   function multiVpcSVG() {
     const subnet = (x, y, title, sub) =>
       `<rect class="d-box" x="${x}" y="${y}" width="224" height="64" rx="6"/>
        <text class="d-title" x="${x + 12}" y="${y + 26}">${title}</text>
        <text class="d-sub" x="${x + 12}" y="${y + 46}">${sub}</text>`;
     return `<svg viewBox="0 0 580 212" role="img" aria-label="Multi-VPC segmentation topology">
       <rect class="d-zone" x="0" y="4" width="248" height="200" rx="8"/>
       <text class="d-sub" x="12" y="24">griffin-dev-vpc · custom mode</text>
       ${subnet(12, 36, "griffin-dev-wp  192.168.16.0/20", "GKE nodes + Cloud SQL Auth Proxy")}
       ${subnet(12, 124, "griffin-dev-mgmt 192.168.32.0/20", "NIC 0 · management plane")}
       <rect class="d-zone" x="332" y="4" width="248" height="200" rx="8"/>
       <text class="d-sub" x="344" y="24">griffin-prod-vpc · custom mode</text>
       ${subnet(344, 36, "griffin-prod-wp  192.168.48.0/20", "Isolated production tier")}
       ${subnet(344, 124, "griffin-prod-mgmt 192.168.64.0/20", "NIC 1 · prod admin plane")}
       <line class="d-line" x1="236" y1="156" x2="344" y2="156"/>
       <rect class="d-key" x="244" y="138" width="92" height="36" rx="6"/>
       <text class="d-title d-accent" x="290" y="154" text-anchor="middle">Bastion VM</text>
       <text class="d-sub" x="290" y="167" text-anchor="middle">dual-NIC SSH</text>
     </svg>`;
   }
   
   const diagram = (type) => (type === "multi-vpc" ? multiVpcSVG() : pipelineSVG(PIPELINES[type] || []));
   
   /* ---------- 4. Section renderers ---------- */
   function renderWork() {
     $("#workList").innerHTML = PORTFOLIO.projects.map((p, i) => `
       <li>
         <button class="work-item" type="button" data-project="${p.id}">
           <span class="work-index">${pad(i + 1)}</span>
           <span>
             <span class="work-meta">${esc(p.category)}${p.verified ? ` · <span class="verified">${esc(p.status)}</span>` : ""}</span>
             <span class="work-title">${esc(p.title)}</span>
             <span class="work-summary">${esc(p.summary)}</span>
             <span class="tags">${p.stack.slice(0, 4).map((t) => `<span>${esc(t)}</span>`).join("")}</span>
           </span>
           <span class="work-arrow" aria-hidden="true">→</span>
         </button>
       </li>`).join("");
   }
   
   function renderRepos(repos) {
     $("#repoList").innerHTML = repos.map((r) => `
       <li>
         <a class="repo" href="${esc(r.url)}" target="_blank" rel="noopener">
           <span class="repo-name">${esc(r.name)}</span>
           <span class="repo-lang">${esc([r.language, formatMonth(r.updated)].filter(Boolean).join(" · "))}</span>
           ${r.description ? `<span class="repo-desc">${esc(r.description)}</span>` : ""}
         </a>
       </li>`).join("");
   }
   
   function renderNotes() {
     $("#noteList").innerHTML = PORTFOLIO.notes.map((n) => `
       <li>
         <button class="note" type="button" data-note="${n.id}">
           <span class="note-date">${esc(n.date)}</span>
           <span>
             <span class="note-title">${esc(n.title)}</span>
             <span class="note-excerpt">${esc(n.excerpt)}</span>
           </span>
         </button>
       </li>`).join("");
   }
   
   function bullet(text) {
     // "Lead – detail" → <strong>Lead</strong> — detail
     const [lead, ...rest] = text.split(" – ");
     return rest.length ? `<strong>${esc(lead)}.</strong> ${esc(rest.join(" – "))}` : esc(text);
   }
   
   function renderExperience() {
     $("#jobList").innerHTML = PORTFOLIO.experience.map((job, i) => `
       <details class="job"${i === 0 ? " open" : ""}>
         <summary>
           <span class="job-period">${esc(job.period)}</span>
           <span>
             <span class="job-role">${esc(job.role)}</span>
             <span class="job-org">${esc(job.org)}</span>
           </span>
           <span class="job-toggle" aria-hidden="true"></span>
         </summary>
         <ul class="list">${job.bullets.map((b) => `<li>${bullet(b)}</li>`).join("")}</ul>
       </details>`).join("");
   
     $("#skillList").innerHTML = PORTFOLIO.skills.map((s) => `
       <div><dt>${esc(s.group)}</dt><dd>${esc(s.items)}</dd></div>`).join("");
   
     $("#credList").innerHTML = PORTFOLIO.credentials.map((c) => `
       <li>
         <a class="cred" href="${esc(c.url)}" target="_blank" rel="noopener">
           <span class="cred-title">${esc(c.title)}</span>
           <span class="cred-issuer">${esc(c.issuer)}</span>
           <span class="cred-status">${esc(c.status)}</span>
         </a>
       </li>`).join("");
   }
   
   /* ---------- 5. Side sheet ---------- */
   const sheet = () => $("#sheet");
   
   function openSheet(html) {
     $("#sheetInner").innerHTML = html;
     sheet().showModal();
     $("#sheetInner .sheet-body").scrollTop = 0;
   }
   
   function projectSheet(p) {
     return `
       <header class="sheet-head">
         <div>
           <p class="eyebrow">${esc(p.category)} · ${esc(p.status)}</p>
           <h2 class="sheet-title" id="sheetTitle">${esc(p.title)}</h2>
         </div>
         <button class="icon-btn" type="button" data-close aria-label="Close">${ICON_CLOSE}</button>
       </header>
       <div class="tabs" role="tablist">
         <button type="button" role="tab" aria-selected="true" data-tab="brief">Brief</button>
         <button type="button" role="tab" aria-selected="false" data-tab="arch">Architecture</button>
         <button type="button" role="tab" aria-selected="false" data-tab="code">${esc(p.artifact.file)}</button>
       </div>
       <div class="sheet-body">
         <section data-panel="brief" role="tabpanel">
           <h3>Problem</h3>
           <p>${esc(p.problem)}</p>
           <h3>Controls</h3>
           <ul class="list">${p.controls.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
           <h3>Verification</h3>
           <p>${esc(p.verification)}</p>
           <h3>Stack</h3>
           <p class="tags">${p.stack.map((t) => `<span>${esc(t)}</span>`).join("")}</p>
         </section>
         <section data-panel="arch" role="tabpanel" hidden>
           <div class="diagram">${diagram(p.diagram)}</div>
         </section>
         <section data-panel="code" role="tabpanel" hidden>
           <div class="code">
             <div class="code-bar"><span>${esc(p.artifact.file)}</span><button type="button" data-copy-code>Copy</button></div>
             <pre><code>${esc(p.artifact.code)}</code></pre>
           </div>
         </section>
       </div>
       <footer class="sheet-foot">
         <a class="btn btn-primary" href="${esc(p.repoUrl)}" target="_blank" rel="noopener">View repository ↗</a>
       </footer>`;
   }
   
   function noteSheet(n) {
     return `
       <header class="sheet-head">
         <div>
           <p class="eyebrow">${esc(n.date)} · ${esc(n.readTime)} read</p>
           <h2 class="sheet-title serif" id="sheetTitle">${esc(n.title)}</h2>
         </div>
         <button class="icon-btn" type="button" data-close aria-label="Close">${ICON_CLOSE}</button>
       </header>
       <div class="sheet-body">
         <p class="pullquote">${esc(n.callout)}</p>
         <article class="article">${n.paragraphs.map((p) => `<p>${esc(p)}</p>`).join("")}</article>
       </div>`;
   }
   
   function selectTab(name) {
     $$("#sheetInner [data-tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
     $$("#sheetInner [data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== name));
   }
   
   /* ---------- 6. GitHub sync ---------- */
   async function syncGitHub() {
     const { githubHandle: user, githubSync, fallbackRepos } = PORTFOLIO;
     renderRepos(fallbackRepos);
     if (!githubSync.enabled) return;
   
     const status = $("#syncStatus");
     const key = `aj-repos:${user}`;
     try {
       const cached = JSON.parse(sessionStorage.getItem(key) || "null");
       if (cached && Date.now() - cached.t < 5 * 60 * 1000 && cached.repos.length) {
         renderRepos(cached.repos);
         status.textContent = "Live from GitHub";
         return;
       }
     } catch { /* ignore bad cache */ }
   
     const ctrl = new AbortController();
     const timer = setTimeout(() => ctrl.abort(), 5000);
     try {
       const res = await fetch(
         `https://api.github.com/users/${encodeURIComponent(user)}/repos?sort=pushed&per_page=30&type=owner`,
         { headers: { Accept: "application/vnd.github+json" }, signal: ctrl.signal }
       );
       if (!res.ok) throw new Error(`HTTP ${res.status}`);
       const data = await res.json();
       const repos = data
         .filter((r) => !r.fork && !r.archived && r.name.toLowerCase() !== `${user.toLowerCase()}.github.io`)
         .slice(0, githubSync.maxRepos)
         .map((r) => ({ name: r.name, description: r.description || "", language: r.language || "", url: r.html_url, updated: r.pushed_at }));
       if (!repos.length) return;
       try { sessionStorage.setItem(key, JSON.stringify({ t: Date.now(), repos })); } catch {}
       renderRepos(repos);
       status.textContent = "Live from GitHub";
     } catch {
       /* offline, rate-limited, or blocked: keep the curated list */
     } finally {
       clearTimeout(timer);
     }
   }
   
   /* ---------- 7. Theme, nav, motion ---------- */
   function initTheme() {
     $("#themeToggle").addEventListener("click", () => {
       const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
       document.documentElement.dataset.theme = next;
       try { localStorage.setItem("aj-theme", next); } catch {}
     });
   }
   
   function initNav() {
     const nav = $("#nav");
     const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 8);
     window.addEventListener("scroll", onScroll, { passive: true });
     onScroll();
   
     if (!("IntersectionObserver" in window)) return;
     const links = $$(".nav-links a");
     const io = new IntersectionObserver((entries) => {
       entries.forEach((e) => {
         if (!e.isIntersecting) return;
         links.forEach((a) => a.setAttribute("aria-current", String(a.hash === `#${e.target.id}`)));
       });
     }, { rootMargin: "-45% 0px -50% 0px" });
     $$("main section[id], footer[id]").forEach((s) => io.observe(s));
   }
   
   function initMotion() {
     if (!("IntersectionObserver" in window) || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
     document.documentElement.classList.add("motion");
     const io = new IntersectionObserver((entries) => {
       entries.forEach((e) => {
         if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
       });
     }, { rootMargin: "0px 0px -8% 0px" });
     $$(".reveal").forEach((el) => io.observe(el));
   }
   
   /* ---------- 8. Events (one delegated listener) ---------- */
   function initEvents() {
     document.addEventListener("click", (e) => {
       const t = e.target.closest("[data-project],[data-note],[data-tab],[data-close],[data-copy],[data-copy-code],[data-print]");
       if (!t) return;
   
       if (t.dataset.project) {
         const p = PORTFOLIO.projects.find((x) => x.id === t.dataset.project);
         if (p) openSheet(projectSheet(p));
       } else if (t.dataset.note) {
         const n = PORTFOLIO.notes.find((x) => x.id === t.dataset.note);
         if (n) openSheet(noteSheet(n));
       } else if (t.dataset.tab) {
         selectTab(t.dataset.tab);
       } else if (t.hasAttribute("data-close")) {
         sheet().close();
       } else if (t.hasAttribute("data-copy-code")) {
         const code = t.closest(".code").querySelector("code").textContent;
         copy(code, "Snippet copied");
       } else if (t.dataset.copy) {
         copy(t.dataset.copy, t.dataset.toast || "Copied");
       } else if (t.hasAttribute("data-print")) {
         window.print();
       }
     });
   
     // Click on the dimmed backdrop closes the sheet (Esc is handled natively by <dialog>)
     sheet().addEventListener("click", (e) => { if (e.target === sheet()) sheet().close(); });
   
     // Expand every role before printing the résumé, then restore
     let openState = [];
     window.addEventListener("beforeprint", () => {
       openState = $$(".job").map((d) => d.open);
       $$(".job").forEach((d) => (d.open = true));
     });
     window.addEventListener("afterprint", () => $$(".job").forEach((d, i) => (d.open = openState[i] ?? d.open)));
   }
   
   /* ---------- 9. Boot ---------- */
   document.addEventListener("DOMContentLoaded", () => {
     $("#year").textContent = new Date().getFullYear();
     renderWork();
     renderNotes();
     renderExperience();
     initTheme();
     initNav();
     initEvents();
     initMotion();
     syncGitHub();
   });