# AI System Reconnaissance 


## Table of Contents

- [Overview](#overview)
- [Scenario](#scenario)
- [Learning Objectives](#learning-objectives)
- [1. Understanding the AI Infrastructure Stack](#1-understanding-the-ai-infrastructure-stack)
- [2. Discovering AI Services with Network Scanning](#2-discovering-ai-services-with-network-scanning)
- [3. Fingerprinting AI Services](#3-fingerprinting-ai-services)
- [4. Enumerating AI Service Metadata](#4-enumerating-ai-service-metadata)
- [5. Mapping the AI Attack Surface](#5-mapping-the-ai-attack-surface)
- [6. Mapping Findings to MITRE ATLAS](#6-mapping-findings-to-mitre-atlas)
- [7. The Five-Phase AI Reconnaissance Methodology](#7-the-five-phase-ai-reconnaissance-methodology)
- [Questions and Answers](#questions-and-answers)
- [Defensive Recommendations](#defensive-recommendations)
- [Industry Framework Mapping](#industry-framework-mapping)
- [Key Takeaways](#key-takeaways)
- [References and Further Learning](#references-and-further-learning)

## Overview

AI reconnaissance is the process of discovering AI and machine-learning (ML) services in an environment, identifying the frameworks behind them, and determining what information their exposed interfaces reveal. The tools may be familiar—such as Nmap, `curl`, and `grep`—but the targets and service signatures differ from those of traditional web infrastructure.

AI deployments can introduce inference endpoints, model registries, experiment-tracking servers, vector databases, notebook servers, object storage, and metrics interfaces. If these components are exposed or insufficiently authenticated, an attacker may be able to map an organisation's AI environment and discover sensitive metadata without exploiting a model directly.

This room focuses on **discovery and enumeration**, rather than exploitation. It complements AI threat modelling: threat modelling asks what could go wrong, while reconnaissance identifies which systems actually exist and what they expose.

## Scenario

You are a security engineer at **Cyphira**, a mid-sized fintech company that deployed AI-powered features without a security review. The CISO wants to know:

- Which AI systems are deployed?
- Which services and APIs are exposed?
- What metadata can be retrieved from those services?
- How could an attacker discover and map the AI attack surface?
- What can defenders do to reduce unnecessary exposure?

The task is to discover and document the environment without damaging or disrupting systems.

## Learning Objectives

- Identify common components of a production AI/ML system and their ports, protocols, and API paths.
- Fingerprint AI services using HTTP headers, JSON responses, error messages, and endpoint names.
- Enumerate model metadata, experiment histories, and deployment configuration from exposed services.
- Map relationships between AI components and their supply-chain dependencies.
- Apply a repeatable AI reconnaissance methodology using established security tools.
- Recognise log patterns that may indicate AI-focused reconnaissance.

---

## 1. Understanding the AI Infrastructure Stack

A production AI system is a collection of services that support model training, deployment, inference, storage, and monitoring. Each component can expose a different interface and a different set of risks.

### Common components and ports

| Component | Default port(s) | Protocol(s) | Useful reconnaissance endpoints |
|---|---:|---|---|
| NVIDIA Triton Inference Server | `8000`, `8001`, `8002` | HTTP, gRPC, Prometheus | `/v2/health/ready`, `/v2/models`, `/metrics` |
| TensorFlow Serving | `8500`, `8501` | gRPC, HTTP | `/v1/models/<name>` |
| TorchServe | `8080`, `8081`, `8082` | HTTP | `/ping`, `/models`, `/metrics` |
| Ollama | `11434` | HTTP | `/api/tags`, `/api/show` |
| vLLM | `8000` | HTTP | `/v1/models` |
| MLflow Tracking Server | `5000` | HTTP | `/api/2.0/mlflow/experiments/search` |
| Kubeflow | `80`, `443` | HTTP/HTTPS | `/pipeline/apis/v1beta1/pipelines` |
| Ray dashboard / API | `8265`, `8000` | HTTP | `/api/jobs/`, dashboard interface |
| Qdrant | `6333`, `6334` | HTTP, gRPC | `/collections` |
| Weaviate | `8080` | HTTP, GraphQL | `/v1/schema`, `/v1/meta` |
| Milvus | `19530` | gRPC | Service connection on port `19530` |
| Jupyter Notebook | `8888` | HTTP | `/api/kernels`, `/api/contents` |
| MinIO | `9000`, `9001` | HTTP, S3-compatible | Object-storage and bucket interfaces |
| Prometheus metrics | Commonly `8002`, `8082` on the examples above | HTTP | `/metrics` |

These ports are common defaults, not guarantees. Administrators can change them, and reverse proxies can hide or alter the visible service signatures.

### Why these services matter

- **Model-serving endpoints** accept requests and return predictions or generated output.
- **Experiment trackers such as MLflow** can reveal experiments, hyperparameters, training metrics, registered models, artifact locations, and creator identities.
- **Vector databases** store embeddings used by semantic search and retrieval-augmented generation (RAG). Collection names, dimensions, and payload schemas may reveal what information is indexed.
- **Model registries and artifact storage** can reveal model versions, deployment stages, and storage locations.
- **Jupyter notebooks** may expose source code, internal paths, and accidentally stored credentials if authentication and access controls are weak.
- **Metrics endpoints** can disclose model names, batch sizes, GPU utilisation, latency, and deployment topology.

### Reconnaissance lesson

An exposed service can reveal more than the service itself. For example, a notebook may contain MLflow credentials, the MLflow registry may reveal artifact URIs, and those URIs may point to object storage containing model files. Reconnaissance is therefore about identifying both components and the connections between them.

---

## 2. Discovering AI Services with Network Scanning

The lab uses a private training subnet, `10.10.45.0/24`. The commands below are intended for the authorised TryHackMe lab environment.

### Scan AI-specific ports

```bash
nmap -p 5000,6333,6334,8000,8001,8002,8888,9000,9001 -sV 10.10.45.0/24
```

This scan checks selected ports associated with services such as MLflow, Qdrant, Triton, Jupyter, and MinIO. Review open ports and the service strings reported by Nmap.

### Compare against traditional services

```bash
nmap -p 22,80,443,5432 -sV 10.10.45.0/24
```

Comparing the results helps distinguish hosts that expose only conventional services from hosts that also run AI infrastructure. Nmap service detection may not identify every AI framework correctly, so treat its output as a starting point rather than a final identification.

### What to record

For each discovered service, record:

- Host IP address
- Open port
- Protocol
- Initial service-detection result
- Suspected AI component
- Evidence needed to confirm the identification

### Lab finding

The supplied lab notes identify `10.10.45.20` as the host running an HTTP service on port `8888`, and state that MLflow Tracking Server uses port `5000` by default.

---

## 3. Fingerprinting AI Services

Fingerprinting identifies the framework behind an open port. Nmap may label an AI HTTP service generically or fail to identify a gRPC service, so the lab recommends examining headers, response bodies, error messages, and endpoint naming conventions.

### HTTP response headers

| Signature | Likely identification |
|---|---|
| `Server: TorchServe/0.x.x` | TorchServe |
| `NV-Status` response header | NVIDIA Triton in the lab's example |
| `Server: uvicorn` together with ML routes such as `/predict` or `/embeddings` | A likely FastAPI-based Python service |
| `x-request-id` and an OpenAI-compatible `/v1/models` response | An OpenAI-compatible API implementation; further checks are needed to identify the exact framework |

### JSON response signatures

| Response clue | What it suggests |
|---|---|
| `model_version_status` with a version state such as `AVAILABLE` | TensorFlow Serving |
| A model object containing `name`, `versions`, and `platform` | Triton model metadata in the lab's example |
| `object: model` and a model `id` on `/v1/models` | An OpenAI-compatible model API |
| Error traces mentioning `mlflow.server` or `mlflow.tracking` | MLflow |

### Endpoint naming conventions

AI-related endpoints often use computational terms rather than ordinary resource names.

| Purpose | Example endpoints |
|---|---|
| Inference | `/predict`, `/invocations`, `/infer`, `/generate`, `/embeddings`, `/score` |
| Model listing | `/v1/models`, `/v2/models` |
| MLflow API | `/api/2.0/mlflow/` |
| Kubeflow pipelines | `/pipeline/apis/v1beta1/` |
| Vector database schema | `/v1/schema`, `/v1/meta`, `/collections` |
| Jupyter API | `/api/kernels`, `/api/contents` |

### Example fingerprinting commands

Inspect the MLflow response headers:

```bash
curl -v http://10.10.45.12:5000/
```

Query Triton's model endpoint:

```bash
curl http://10.10.45.15:8000/v2/models
```

Send a deliberately malformed request only within the authorised lab to observe the framework's error format:

```bash
curl -X POST http://10.10.45.15:8000/v2/models/fraud_detector/infer \
  -H 'Content-Type: application/json' \
  -d '{"bad":"data"}'
```

Check whether gRPC reflection is available:

```bash
grpcurl -plaintext 10.10.45.15:8001 list
```

Probe the vector database and notebook APIs:

```bash
curl http://10.10.45.18:6333/collections
curl http://10.10.45.20:8888/api/kernels
```

### Lab findings

The supplied notes identify the `NV-Status` header on `10.10.45.15:8000` as an NVIDIA-related signature. They also record `inference.GRPCInferenceService` as the service name returned by the gRPC reflection query on port `8001`.

---

## 4. Enumerating AI Service Metadata

Fingerprinting answers, “What service is this?” Enumeration asks, “What information does this service expose?”

### MLflow

The lab demonstrates querying MLflow for experiment and model information, including registered models, versions, artifact locations, and creator identifiers.

Example endpoint used in the lab:

```text
/api/2.0/mlflow/model-versions/search
```

The endpoint is used in the supplied notes to retrieve model-version details, including artifact URIs. Treat any returned storage location or identity information as sensitive.

### Triton model configuration

```bash
curl http://10.10.45.15:8000/v2/models/fraud_detector/config
```

The configuration can reveal model input names, tensor shapes, data types, and maximum batch size. This describes how the model expects requests to be structured and may disclose implementation details.

### Qdrant collection information

```bash
curl http://10.10.45.18:6333/collections/internal-kb-embeddings
```

Collection metadata may reveal vector dimensions, point counts, and payload fields. These clues can help a defender understand what kind of data the RAG system indexes.

### Jupyter contents and kernels

```bash
curl http://10.10.45.20:8888/api/contents
curl http://10.10.45.20:8888/api/kernels
```

When these interfaces are accessible without appropriate authentication, they may reveal notebook names, kernel information, source code, and accidentally stored credentials. Access should be restricted to authorised users and networks.

### Important handling note

The source lab notes include a cleartext password discovered in a lab notebook. It is retained below in the answer section because it is one of the supplied lab answers. Do not reuse lab credentials, and do not publish real operational secrets in a public repository. If a similar credential is found in a real environment, treat it as compromised and rotate it.

---

## 5. Mapping the AI Attack Surface

AI components communicate with each other throughout the model lifecycle:

- Inference services may retrieve features or context from vector databases.
- Orchestration platforms may push model updates to registries.
- Notebooks may connect to tracking servers, storage, and internal APIs.
- Monitoring systems may scrape metrics from model-serving endpoints.
- Model artifacts may be downloaded from internal or third-party repositories.

A weakly protected component can expose information about other systems and provide paths to additional resources. The security boundary is therefore not just the external firewall; internal service-to-service access, credentials, and artifact dependencies also matter.

### Examples of risks revealed by reconnaissance

| Finding | Potential impact |
|---|---|
| Exposed MLflow tracking server | Experiment, model-version, and artifact metadata disclosure |
| Unauthenticated notebook interface | Source-code and configuration exposure; possible credential leakage |
| Publicly reachable metrics endpoint | Disclosure of model names, resource usage, and topology |
| Exposed model registry or artifact URI | Easier discovery of model files and storage locations |
| Leaked third-party model token | Unauthorised access within the token's permission scope |
| Unprotected vector database | Disclosure of collection structure and potentially indexed content |
| Broad internal network access | A compromise in one component may affect connected services |

### Mapping findings to MITRE ATLAS

The lab asks learners to map observed reconnaissance activities and supply-chain exposure to MITRE ATLAS technique identifiers. The supplied notes give these answers:

- Exposed AI supply-chain dependencies: `AML.T0010`
- Overarching reconnaissance tactic: `AML.TA0002`

Use framework identifiers as a common vocabulary for documenting activity. Confirm mappings against the current framework when writing a real assessment, since framework names and taxonomies can evolve.

---

## 6. Mapping Findings to MITRE ATLAS

The room presents **MITRE ATLAS** as a framework for describing adversary tactics and techniques targeting AI systems. It also relates AI reconnaissance to traditional MITRE ATT&CK Enterprise techniques.

### ATLAS mapping from the lab notes

| Room activity | Identifier supplied | Name supplied in the notes |
|---|---|---|
| Public research and internet-facing discovery | `AML.T0000` | Search for Victim's Publicly Available Research Materials (as described in the room's methodology) |
| Locating model registries and artifacts through unsecured APIs | `AML.T0048` | Discover ML Artifacts |
| Exposed tokens and dependency-confusion risks | `AML.T0040` | ML Supply Chain Compromise |
| Enumerating LLM configuration and API schema compatibility | `AML.T0069` | Discover LLM System Information |
| Reconnaissance activities collectively | `AML.TA0002` | Reconnaissance tactic |

### Traditional MITRE ATT&CK mapping from the lab notes

| Activity | Identifier | Technique name |
|---|---|---|
| Port scanning for AI-specific services | `T1046` | Network Service Scanning |
| Extracting deployment topology from metrics and metadata | `T1592` | Gather Victim Host Information |
| Probing management interfaces for vulnerabilities | `T1595.002` | Vulnerability Scanning |
| Collecting intelligence before an engagement | `TA0043` | Reconnaissance tactic |

These mappings are reproduced from the supplied room notes. For professional reporting, verify the current technique names and IDs in the official MITRE resources before finalising a finding.

---

## 7. The Five-Phase AI Reconnaissance Methodology

The room consolidates its approach into five phases.

### Phase 1 — Passive Reconnaissance

Before directly probing a target, review information already available publicly:

- Search internet-wide indexes such as Shodan, Censys, and FOFA for exposed AI service banners.
- Search public repositories for accidentally exposed configuration and credentials.
- Review published research, engineering blogs, job postings, and container registries for clues about deployed frameworks.

Passive discovery should be conducted within the scope and rules of the engagement.

### Phase 2 — Active Scanning

Scan approved target ranges for AI-specific ports, then follow up on likely HTTP and gRPC services.

Example from the room:

```bash
nmap -p 5000,6333,8000,8001,8002,8080,8265,8500,8501,8888,9000,11434,19530 \
  -sV --script=http-title,http-headers <target>
```

Record open ports, service versions, and potential metrics endpoints. Follow up on gRPC services with suitable gRPC tooling when authorised.

### Phase 3 — API Fingerprinting

Probe discovered HTTP services for AI-specific endpoints, then inspect:

- Response headers
- JSON structure
- Error messages
- Endpoint naming conventions
- API documentation or schema endpoints

The room's example endpoint list includes `/v1/models`, `/v2/models`, `/v2/health/ready`, `/api/2.0/mlflow/`, `/pipeline/apis/v1beta1/pipelines`, `/v1/schema`, `/v1/meta`, `/api/kernels`, `/api/contents`, `/openapi.json`, `/docs`, `/graphql`, `/metrics`, `/api/tags`, `/api/show`, `/collections`, `/healthz`, and `/ping`.

### Phase 4 — Metadata Extraction

For each confirmed service, collect only the information needed for the authorised assessment:

- **MLflow:** experiments, registered models, versions, artifact URIs, and model-version metadata.
- **Triton or TensorFlow Serving:** model names and configuration details.
- **Vector databases:** collection names, dimensions, counts, and schema information.
- **Jupyter:** exposed notebook metadata and evidence of configuration or secret leakage.
- **Metrics endpoints:** model identifiers, performance details, and infrastructure clues.

Handle any credentials, personal information, or proprietary model metadata as sensitive evidence.

### Phase 5 — Supply-Chain Review

Review model and dependency sources identified during reconnaissance:

- Identify model download sources and third-party dependencies.
- Check whether artifact storage is unintentionally public.
- Review dependency manifests for internal package names and dependency-confusion exposure.
- Inspect container-registry access controls.
- Identify exposed tokens and assess their scope; rotate any real credentials that may have been compromised.

### Tool reference

| Tool | Purpose in the room | Phase |
|---|---|---|
| Shodan / Censys / FOFA | Search for internet-exposed service banners | Passive reconnaissance |
| Public code search | Find exposed configuration and credentials | Passive reconnaissance |
| Nmap | Discover ports and detect service versions | Active scanning |
| `grpcurl` | Inspect reachable gRPC services and reflection, where enabled | Active scanning / fingerprinting |
| `ffuf` / `feroxbuster` | Discover web paths using an authorised wordlist | Scanning / fingerprinting |
| `curl` | Inspect headers, endpoints, and response bodies | Fingerprinting / enumeration |
| MLOKit | Automate selected MLflow enumeration tasks, as described in the room | Metadata extraction |
| Nuclei | Run templates for known service exposures and misconfigurations | Scanning / fingerprinting |
| Agrus Scanner | AI-focused discovery, as described in the room | Active scanning |

---

## Questions and Answers

The following answers are reproduced from the supplied lab notes and kept in the order of the room's questions.

### Task 2 — Network Discovery

**Q1. What is the IP address of the host running an HTTP service on port 8888 in the scan results?**

**Answer:** `10.10.45.20`

**Q2. Which port does MLflow Tracking Server run on by default?**

**Answer:** `5000`

### Task 3 — Service Fingerprinting

**Q3. Which unique HTTP response header does the service on `10.10.45.15:8000` return to identify as an NVIDIA product?**

**Answer:** `NV-Status`

**Q4. When you run `grpcurl` against `10.10.45.15:8001`, what is the name of the inference service listed in the reflection output?**

**Answer:** `inference.GRPCInferenceService`

### Task 4 — Metadata Enumeration

**Q5. What MLflow REST API endpoint would you use to retrieve the artifact storage location for a specific model version?**

**Answer:** `/api/2.0/mlflow/model-versions/search`

**Q6. What is the cleartext password for the MLflow service account stored in the Jupyter notebook on `10.10.45.20`?**

**Answer supplied in the lab notes:** `Cyphira-MLfl0w-2024!`

> **Credential-handling note:** This is reproduced as a lab answer from the provided source. Never reuse it outside the lab. If a comparable password is found in a real environment, treat it as compromised, rotate it, and investigate where it was exposed.

### Task 5 — Supply-Chain and ATLAS Mapping

**Q7. Which ATLAS technique ID covers the risk of exposed supply-chain dependencies described in the question?**

**Answer:** `AML.T0010`

**Q8. What is the ID of the overarching ATLAS tactic that covers scanning the subnet, probing endpoints, and extracting metadata from MLflow APIs?**

**Answer:** `AML.TA0002`

### Task 6 — Detection and Defence

**Q9. A SIEM log shows requests to `/api/2.0/mlflow/registered-models/list` from an IP with no corresponding MLflow UI session. What tool's access pattern does this match?**

**Answer:** `MLOKit`

**Q10. What is the single most effective quick win for preventing unauthenticated access to the MLflow tracking server?**

**Answer:** `Enable MLflow authentication`

### Quick Answer Reference

| # | Answer |
|---:|---|
| 1 | `10.10.45.20` |
| 2 | `5000` |
| 3 | `NV-Status` |
| 4 | `inference.GRPCInferenceService` |
| 5 | `/api/2.0/mlflow/model-versions/search` |
| 6 | `Cyphira-MLfl0w-2024!` |
| 7 | `AML.T0010` |
| 8 | `AML.TA0002` |
| 9 | `MLOKit` |
| 10 | `Enable MLflow authentication` |

---

## Defensive Recommendations

The room's suggested quick wins include:

1. **Require authentication for MLflow.** Configure authentication or place the service behind an authenticating reverse proxy.
2. **Secure Jupyter.** Require token or equivalent authentication, restrict network reachability, and avoid exposing notebook servers directly to untrusted networks.
3. **Restrict AI service ports.** Keep model-serving, orchestration, notebook, registry, and object-storage interfaces private unless external exposure is explicitly required.
4. **Restrict metrics access.** Allow `/metrics` only from approved monitoring systems.
5. **Limit model-control permissions.** Review whether production inference servers need model loading and unloading capabilities.
6. **Rotate and scope tokens.** Use least-privilege, fine-grained tokens and revoke credentials that may have been exposed.
7. **Reduce information leakage.** Remove unnecessary debug headers and verbose errors from responses exposed to untrusted networks.
8. **Secure model artifacts.** Audit S3, GCS, MinIO, and other artifact-storage policies; do not make model files publicly readable without an explicit requirement.
9. **Segment internal services.** Limit which components can communicate with notebooks, registries, vector databases, and inference endpoints.
10. **Monitor reconnaissance patterns.** Alert on repeated model-listing requests, scripted MLflow API access, unexpected external metrics scraping, AI-specific port scans, path-traversal probes, and unauthenticated Jupyter API requests.

### What reconnaissance may look like in SIEM logs

| Pattern | Why it may be suspicious |
|---|---|
| Repeated sequential requests to `/v2/models` | May indicate scripted model enumeration |
| MLflow API calls without normal UI-session activity | May indicate automated metadata collection |
| Requests to `/metrics` from outside the monitoring network | May expose an unexpected observer of infrastructure metrics |
| Sequential scans of common AI ports | May indicate targeted discovery of AI services |
| `../` or encoded traversal sequences against artifact endpoints | May indicate path-traversal probing |
| Jupyter `/api/kernels` or `/api/contents` requests without a valid session | May indicate unauthorised notebook enumeration |

These patterns are indicators, not proof of malicious activity. Correlate them with source identity, expected automation, network context, and other telemetry before classifying an event.

---

## Industry Framework Mapping

The supplied room notes relate the work to the following frameworks.

### MITRE ATLAS

Use ATLAS to describe AI-focused adversary tactics and techniques. The room maps passive discovery, artifact discovery, supply-chain compromise, LLM system-information discovery, and reconnaissance to ATLAS identifiers.

### MITRE ATT&CK Enterprise

Traditional reconnaissance and scanning techniques also apply to AI infrastructure, including network service scanning (`T1046`), gathering host information (`T1592`), vulnerability scanning (`T1595.002`), and the reconnaissance tactic (`TA0043`).

### OWASP Top 10 for LLM Applications (2025)

The room discusses how exposed AI APIs, artifacts, tokens, and management interfaces relate to LLM application risks. The specific mappings in the source notes should be checked against the official OWASP taxonomy before being reused in a formal report.

### NIST AI Risk Management Framework (AI RMF 1.0)

The room connects reconnaissance to the **Map** function, particularly identifying AI system components, interactions, potential risks, and third-party dependencies. Monitoring and interface observations may also inform the **Measure** function.

### NIST Cybersecurity Framework (CSF 2.0)

The work supports the **Identify** function, particularly asset management (`ID.AM`) and risk assessment (`ID.RA`): an organisation cannot effectively assess or protect AI systems it has not discovered.

---

## Key Takeaways

- AI infrastructure includes much more than an inference endpoint: registries, experiment trackers, notebooks, vector databases, artifact stores, and metrics interfaces can all expand the attack surface.
- Default ports are useful discovery clues, but they do not prove a service's identity.
- HTTP headers, JSON structures, endpoint paths, and error messages can help fingerprint AI frameworks.
- Enumeration can reveal model names, versions, configurations, artifact locations, and deployment relationships.
- Credentials accidentally stored in notebooks or configuration files can connect otherwise separate components.
- Reconnaissance should document evidence and relationships, not merely produce a list of open ports.
- Defenders should restrict access, require authentication, rotate exposed credentials, segment internal services, and monitor AI-specific reconnaissance patterns.
- The next step after discovery is to validate findings, assess impact, and prioritise remediation.

## References and Further Learning

The room points toward these resources and tool families for continued study:

- **MITRE ATLAS** — AI adversary tactics, techniques, and mitigations.
- **MITRE ATT&CK Enterprise** — conventional reconnaissance and scanning techniques.
- **OWASP Top 10 for LLM Applications** — LLM application risk categories.
- **NIST AI RMF 1.0** — AI risk-management functions and guidance.
- **NIST Cybersecurity Framework 2.0** — asset identification and risk-management practices.
- **Nmap, curl, and grpcurl** — service discovery and protocol-level inspection.

