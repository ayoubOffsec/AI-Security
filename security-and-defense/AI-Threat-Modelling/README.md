
# AI Threat Modelling 

## Table of Contents

- [Overview](#overview)
- [Learning Objectives](#learning-objectives)
- [Scenario: MegaCorp](#scenario-megacorp)
- [1. AI Assets and Attack Surfaces](#1-ai-assets-and-attack-surfaces)
- [2. The AI Data Supply Chain](#2-the-ai-data-supply-chain)
- [3. Adapting STRIDE for AI](#3-adapting-stride-for-ai)
- [4. MITRE ATLAS](#4-mitre-atlas)
- [5. OWASP LLM Top 10 (2025)](#5-owasp-llm-top-10-2025)
- [6. AI Threat Modelling Exercise](#6-ai-threat-modelling-exercise)
- [Questions and Answers](#questions-and-answers)
- [Key Takeaways](#key-takeaways)
- [References and Further Learning](#references-and-further-learning)

## Overview

Artificial intelligence is already embedded in enterprise operations. Large language models (LLMs) may handle customer support, recommendation engines may personalise products, and machine-learning (ML) models may make real-time fraud decisions.

These deployments introduce attack surfaces that traditional application threat modelling may not fully capture. Examples include poisoned training data, stolen model weights, prompt injection, manipulated embeddings, and unpredictable model outputs.

This room presents a defender-focused workflow for identifying, classifying, and documenting AI/ML threats. It combines three complementary approaches:

- **STRIDE-AI:** categorises threats by type.
- **MITRE ATLAS:** provides AI-specific adversary techniques and mitigations.
- **OWASP LLM Top 10 (2025):** maps LLM risks to the architectural components where they may occur.

## Learning Objectives

- Identify AI-specific assets and attack surfaces.
- Apply STRIDE threat categories to AI/ML components.
- Use MITRE ATLAS to enumerate adversarial techniques targeting AI systems.
- Map OWASP LLM Top 10 risks to architectural components.
- Produce a structured threat assessment for an AI deployment.

## Scenario: MegaCorp

MegaCorp uses AI in three important business functions:

1. **Customer-facing chatbot:** an LLM connected to internal knowledge bases through a retrieval-augmented generation (RAG) pipeline.
2. **Recommendation engine:** processes sensitive customer data to personalise product recommendations.
3. **Fraud detection system:** makes real-time authorisation decisions on financial transactions.

The security team must assess these deployments and explain the organisation's exposure to AI-specific risks.

---

## 1. AI Assets and Attack Surfaces

AI systems introduce assets that may not be represented adequately in a traditional application asset inventory.

| Asset | Description | Security significance |
|---|---|---|
| Training data | Datasets used to teach the model its behaviour | Poisoning can corrupt learned behaviour and affect future outputs. |
| Model weights / parameters | Numerical values representing what the model has learned | Theft can expose the organisation's trained model and intellectual property. |
| Embedding vectors | Numerical representations used for similarity search, retrieval, or model features | Manipulation can change which information is retrieved or supplied to a model. |
| System prompts | Instructions that define model behaviour, constraints, and persona | Leakage can reveal internal logic and guardrails. |
| Feature stores | Repositories of processed data used as real-time model inputs | Tampering can alter what a model sees at inference time. |
| Model registry / artifacts | Stored, versioned models prepared for deployment | Compromise can allow a legitimate model to be replaced with a modified one. |

### What makes AI systems different?

- **Non-deterministic behaviour:** the same input may produce different outputs, making testing and incident reproduction harder.
- **Black-box behaviour:** the internal reasoning of many models is difficult to inspect directly, so defenders often assess input-output behaviour and failure modes.

### Questions and Answers

**Q1. In a RAG-based system, which AI asset type is used to retrieve relevant context at query time?**

**Answer:** `Embedding Vectors`

**Q2. An attacker gains access to MegaCorp's model registry and swaps the production model for a modified version. Which AI-specific asset has been compromised?**

**Answer:** `Model Registry / Artifacts`

---

## 2. The AI Data Supply Chain

AI systems have a data supply chain in addition to the software supply chain. Every stage can introduce an opportunity for compromise.

### Stages of the AI data supply chain

1. **Data collection:** data may come from web scraping, purchased datasets, internal databases, user-generated content, and third-party providers. An attacker who can influence a source may introduce malicious data.
2. **Cleaning and labelling:** data is filtered, processed, and labelled. Incorrect or compromised labels can teach the model incorrect associations.
3. **Model training:** patterns from prepared data are incorporated into model weights. Poison that survives earlier stages can become part of the trained model.
4. **Validation and packaging:** the model is evaluated, versioned, and stored in a registry. A compromised registry may allow a backdoored model to replace a validated one.
5. **Inference:** the model serves predictions in production. In LLM systems, RAG retrieval can introduce additional content-based injection points.

### Why poisoning can be difficult to detect

The impact of poisoned training data may remain hidden until the model is retrained and deployed. A backdoored model may behave normally during validation if the specific trigger inputs are absent from the validation dataset.

For MegaCorp, crafted transactions inserted over several retraining cycles could gradually shift a fraud detection model's decision boundaries, making particular fraud patterns harder to detect.

### Why STRIDE alone can fall short

Traditional STRIDE is useful, but training-data poisoning has delayed and diffuse effects that may not resemble ordinary modification of a database record. Adversarial inputs can also cross several categories, while model extraction represents a form of intellectual-property loss that differs from conventional data disclosure.

### Questions and Answers

**Q3. An attacker injects crafted data points into a training pipeline over several months, gradually shifting the model's decision boundaries. At which supply chain stage does the attacker inject the malicious data?**

**Answer:** `Data Collection`

**Q4. Which STRIDE category is insufficient for capturing the delayed, diffuse effects of training data poisoning?**

**Answer provided in the lab notes:** `Tapering`

---

## 3. Adapting STRIDE for AI

STRIDE is a threat-modelling framework made up of six categories. The categories remain useful for AI systems, but their manifestations need to be interpreted in the AI context.

| Category | Security property | Traditional meaning | AI-specific manifestation |
|---|---|---|---|
| **S — Spoofing** | Authenticity | Impersonating a legitimate user or service | Data-source impersonation, model impersonation, or adversarial identity inputs |
| **T — Tampering** | Integrity | Unauthorised modification of data or code | Data poisoning, model manipulation, prompt injection in some contexts, and feature manipulation |
| **R — Repudiation** | Non-repudiability | Denying an action due to insufficient evidence | Inability to reconstruct or audit a model decision |
| **I — Information Disclosure** | Confidentiality | Exposing information to unauthorised parties | Model extraction, training-data extraction, system-prompt leakage, or embedding inversion |
| **D — Denial of Service** | Availability | Making a system or resource unavailable | Inference-cost exploitation, GPU exhaustion, or training-pipeline disruption |
| **E — Elevation of Privilege** | Authorisation | Gaining unauthorised access or capabilities | Jailbreaking, guardrail bypass, excessive agency, or unintended tool use |

### S — Spoofing: Data-source impersonation

In a RAG architecture, a model retrieves context from sources such as vector databases, document stores, and web content. If an attacker injects fabricated content into a source that the model trusts, the model may generate answers based on attacker-controlled information.

**MegaCorp example:** fabricated policy documents are inserted into the chatbot's knowledge base, causing it to provide incorrect information to customers.

### T — Tampering: Data poisoning

Poisoning introduces malicious data into a training pipeline so that the model learns incorrect patterns. The effects may only appear during inference.

Other examples include:

- Replacing a model with a modified version.
- Altering features used as model inputs.
- Prompt injection, when the attacker manipulates model input or context. Its STRIDE classification depends on the objective and context.

**MITRE ATLAS techniques noted in the lab:**
- Data Poisoning — `AML.T0020`
- Backdoor ML Model — `AML.T0018`

### R — Repudiation: Inadequate decision audit trails

A team may be unable to explain a past model decision if it has not logged the inputs, outputs, model version, retrieval context, and other relevant settings.

**MegaCorp example:** a regulator asks why a suspicious transaction was approved, but the team cannot identify the model version or features involved.

### I — Information Disclosure: Model extraction

An attacker may query a model API repeatedly and use the input-output pairs to reconstruct a functionally similar model, without accessing its internal weights.

Other risks include training-data extraction, system-prompt leakage, and embedding inversion.

**MegaCorp example:** a competitor collects recommendation-engine responses and confidence scores to build a shadow model.

**MITRE ATLAS techniques noted in the lab:**
- Extract ML Model — `AML.T0024`
- Infer Training Data Membership — `AML.T0025`

### D — Denial of Service: Inference-cost exploitation

AI requests can be expensive to process. A high volume of complex prompts or requests for long outputs can increase operating costs even when the service remains online. This is commonly called **denial of wallet**.

Other risks include GPU resource exhaustion, sponge examples, and training-pipeline disruption.

**MegaCorp example:** expensive chatbot prompts increase the monthly inference bill from `$15,000` to `$180,000` while the service remains available.

**OWASP entry noted in the lab:** `LLM10:2025 — Unbounded Consumption`

### E — Elevation of Privilege: Jailbreaking and excessive agency

Jailbreaking attempts to make an LLM ignore its safety rules or restrictions. The risk becomes more serious when the model has access to tools such as databases, email, web browsing, or code execution.

**MegaCorp example:** a jailbroken chatbot misuses overly broad database tools to retrieve customer personally identifiable information (PII).

**OWASP entry noted in the lab:** `LLM06:2025 — Excessive Agency`

### What STRIDE still misses

Some AI risks do not fit neatly into a single STRIDE category:

- **Adversarial examples:** may overlap with Tampering, Spoofing, and Elevation of Privilege.
- **Model bias and fairness:** may create significant regulatory and compliance concerns without fitting a conventional attack category.
- **Emergent behaviours:** unexpected model capabilities or behaviours can be difficult to anticipate in advance.

### Consolidated STRIDE-AI mapping

| STRIDE category | Primary AI manifestation | MegaCorp example |
|---|---|---|
| Spoofing | Data-source impersonation / RAG injection | Fake policy documents inserted into the chatbot knowledge base |
| Tampering | Data poisoning | Crafted transactions shift fraud-model decision boundaries |
| Repudiation | Missing decision audit trails | The team cannot explain a past fraud decision |
| Information Disclosure | Model extraction | A competitor reconstructs the recommendation logic through API queries |
| Denial of Service | Inference-cost exploitation | Expensive prompts cause a sharp increase in the inference bill |
| Elevation of Privilege | Jailbreaking / guardrail bypass | A chatbot misuses database tools to access customer PII |

### Questions and Answers

**Q5. What is the primary AI-specific manifestation of Information Disclosure in the STRIDE-AI mapping?**

**Answer:** `Model Extraction`

**Q6. An attacker crafts prompts that cause an LLM to bypass its safety guidelines and content restrictions. Which STRIDE category does this map to?**

**Answer:** `Elevation of Privilege`

**Q7. Which OWASP LLM Top 10 (2025) entry addresses the risks of AI systems being granted too many permissions or too much autonomy?**

**Answer:** `LLM06: 2025 — Excessive Agency`

**Q8. An attacker drives your monthly inference bill from $15,000 to $180,000 without taking your service offline. What is this type of attack commonly called?**

**Answer:** `Denial of Wallet`

---

## 4. MITRE ATLAS

**ATLAS** stands for **Adversarial Threat Landscape for Artificial-Intelligence Systems**. It is a knowledge base of adversary tactics and techniques targeting AI and ML systems, and is described in the room as an AI-focused counterpart to MITRE ATT&CK.

The room's early-2026 snapshot reports 16 tactics, 155 techniques, 35 mitigations, and 52 real-world case studies. These figures can change as ATLAS is updated.

### ATLAS structure

| Component | Purpose | Example from the room |
|---|---|---|
| Tactic | Describes the adversary's goal | ML Attack Staging (`AML.TA0012`) |
| Technique | Describes how the goal is pursued | Data Poisoning (`AML.T0020`) |
| Sub-technique | Describes a specific variant | Craft Adversarial Data (`AML.T0043.004`) |
| Mitigation | Describes a defensive countermeasure | Input validation or data-provenance tracking |

### Key techniques

| Technique | ID | Description | STRIDE relationship described in the room |
|---|---|---|---|
| Data Poisoning | `AML.T0020` | Malicious data is injected into training pipelines to corrupt model behaviour | Tampering |
| Model Extraction | `AML.T0024` | API queries are used to reconstruct a functional copy of a model | Information Disclosure |
| Evade ML Model | `AML.T0015` | Adversarial data causes a model to misidentify or misclassify an input | May span Tampering, Spoofing, and Elevation of Privilege |
| LLM Prompt Injection | `AML.T0051` | Direct or indirect instructions manipulate an LLM's behaviour | Tampering, as described in the room |
| Backdoor ML Model | `AML.T0018` | A hidden trigger causes malicious behaviour while ordinary inputs may appear normal | Model tampering / poisoning context |

### Direct vs. indirect prompt injection

- **Direct prompt injection:** malicious instructions are supplied through user input.
- **Indirect prompt injection:** malicious instructions are embedded in content the model retrieves or processes, such as documents in a RAG pipeline.

For MegaCorp, indirect injection through the chatbot's knowledge base is an important threat to assess.

### Using ATLAS in threat modelling

1. Start with STRIDE to identify what could go wrong in each component.
2. Map the threat to a relevant ATLAS technique to describe how an attacker might carry it out.
3. Use the technique's defensive guidance to identify mitigations and turn the threat into an actionable finding.

For example, a training-pipeline tampering risk can be mapped to Data Poisoning (`AML.T0020`). Potential defensive measures mentioned in the room include data-provenance tracking, anomaly detection on training inputs, and model-performance monitoring for drift.

### Case studies

- **ShadowRay (`AML.CS0023`):** exploitation of vulnerabilities in Ray, a framework used for distributed AI workloads, to compromise AI training infrastructure.
- **Morris II Worm (`AML.CS0024`):** a demonstrated self-replicating prompt-injection worm that could spread between AI agents through RAG-based email systems.

### Questions and Answers

**Q9. What does the acronym ATLAS stand for?**

**Answer:** `Adversarial Threat Landscape for Artificial-Intelligence Systems`

**Q10. Which ATLAS case study described a self-replicating prompt injection worm that spread between AI agents via RAG email systems?**

**Answer:** `Morris II`

**Q11. What is the ATLAS technique ID for Model Extraction?**

**Answer:** `AML.T0024`

---

## 5. OWASP LLM Top 10 (2025)

The OWASP Top 10 for LLM Applications identifies major security risks associated with LLM deployments. In this room, it is used to map threats to the architectural components where they may occur.

### Risk-to-component mapping

| ID | Risk | Meaning | Vulnerable components described in the room |
|---|---|---|---|
| LLM01 | Prompt Injection | Crafted direct or indirect inputs manipulate model behaviour | Inference endpoint, vector database, RAG pipeline, and other components feeding text to the model |
| LLM02 | Sensitive Information Disclosure | Outputs reveal PII, credentials, or proprietary information | Inference endpoint, training pipeline, system prompt |
| LLM03 | Supply Chain | Models, datasets, plugins, or dependencies are compromised | Training pipeline, model registry, plugin/tool integrations |
| LLM04 | Data and Model Poisoning | Corrupted data or model weights alter behaviour | Training pipeline, model registry, feature store |
| LLM05 | Improper Output Handling | Model outputs are used downstream without suitable validation | Web frontend, API gateway, and systems consuming model responses |
| LLM06 | Excessive Agency | The model has excessive permissions, tools, or autonomy | Inference endpoint, tool integrations, API gateway, agentic orchestration layer |
| LLM07 | System Prompt Leakage | Internal instructions or sensitive information in prompts are exposed | Inference endpoint, system-prompt configuration |
| LLM08 | Vector and Embedding Weaknesses | Weaknesses affect RAG, vector databases, or embeddings | Vector database, RAG pipeline, embedding-generation process |
| LLM09 | Misinformation | The model produces credible-sounding but false content | Inference endpoint, vector database, user-facing output channels |
| LLM10 | Unbounded Consumption | Uncontrolled resource use enables availability or financial attacks | Inference endpoint, API gateway, training pipeline |

### Component risk profiles

#### LLM inference endpoint

The room identifies seven entries affecting this component:

- LLM01 — Prompt Injection
- LLM02 — Sensitive Information Disclosure
- LLM05 — Improper Output Handling
- LLM06 — Excessive Agency
- LLM07 — System Prompt Leakage
- LLM09 — Misinformation
- LLM10 — Unbounded Consumption

#### Vector database / RAG pipeline

The room identifies these key risks:

- LLM01 — Indirect prompt injection through retrieved content
- LLM08 — Vector and embedding weaknesses
- LLM09 — Misinformation from stale or incorrect source documents

The room highlights input validation for indexed content, access controls for the vector store, and freshness monitoring for source documents.

#### Training pipeline

The room identifies these key risks:

- LLM02 — Sensitive information entering training data
- LLM03 — Third-party datasets, compromised base models, or poisoned fine-tuning data
- LLM04 — Data and model poisoning

Supply-chain risk also affects plugin/tool integrations, but the training pipeline is a primary entry point for third-party models and datasets.

### How the frameworks work together

| Framework | Role | Key question |
|---|---|---|
| STRIDE-AI | Categorises threats | What could go wrong? |
| MITRE ATLAS | Describes adversary techniques | How might an attacker do it? |
| OWASP LLM Top 10 | Maps risks to components and helps scope assessment | Where does the risk live? |

### Questions and Answers

**Q12. How many of the OWASP LLM Top 10 entries affect the LLM Inference Endpoint?**

**Answer:** `7`

**Q13. An organisation notices their chatbot is rendering LLM output directly in the browser without sanitisation. Which OWASP entry does this fall under?**

**Answer:** `Improper Output Handling`

**Q14. Which component in a typical LLM architecture is the primary one that needs hardening against data and model supply chain risks (LLM03)?**

**Answer:** `Training Pipeline`

---

## 6. AI Threat Modelling Exercise

The room's practical exercise asks the learner to select OWASP LLM Top 10 vulnerabilities, map them to architecture components, and justify the selections.

**Flag recorded in the supplied lab notes:** `THM{***************}`

> The flag is masked in the supplied file, so the actual flag value is not available in these notes.

---

## Questions and Answers

This section consolidates the answers supplied in the lab notes, in the order they appear.

| # | Question (shortened) | Answer supplied |
|---:|---|---|
| 1 | RAG asset used to retrieve relevant context at query time | `Embedding Vectors` |
| 2 | Asset compromised when a production model is swapped through the registry | `Model Registry / Artifacts` |
| 3 | Supply-chain stage where crafted malicious training data is injected | `Data Collection` |
| 4 | STRIDE category stated as insufficient for delayed, diffuse poisoning effects | `Tapering` |
| 5 | Primary AI-specific Information Disclosure manifestation | `Model Extraction` |
| 6 | STRIDE category for prompts bypassing LLM safety restrictions | `Elevation of Privilege` |
| 7 | OWASP 2025 entry for excessive permissions or autonomy | `LLM06: 2025 — Excessive Agency` |
| 8 | Attack that raises costs without taking the service offline | `Denial of Wallet` |
| 9 | Meaning of ATLAS | `Adversarial Threat Landscape for Artificial-Intelligence Systems` |
| 10 | Self-replicating prompt-injection worm case study | `Morris II` |
| 11 | ATLAS technique ID for Model Extraction | `AML.T0024` |
| 12 | Number of OWASP entries affecting the inference endpoint | `7` |
| 13 | LLM output rendered in a browser without sanitisation | `Improper Output Handling` |
| 14 | Primary component to harden for LLM03 supply-chain risks | `Training Pipeline` |
| 15 | Practical exercise flag | `THM{***************}` (masked in source notes) |

## Key Takeaways

- AI systems have assets beyond conventional application data, including model weights, training data, embeddings, system prompts, feature stores, and model registries.
- The AI data supply chain extends from data collection to inference. A compromise early in the pipeline may remain undetected until after training and deployment.
- STRIDE remains useful, but AI threats require context-specific interpretation and may span multiple categories.
- MITRE ATLAS adds a catalogue of AI-specific adversary techniques and defensive mitigations.
- OWASP LLM Top 10 helps map risks to the components that need assessment and protection.
- Threat modelling should be repeated when an AI system, model, data source, or tool permission changes.
- Useful defensive themes in this room include data provenance, anomaly detection, model-performance monitoring, access controls, input validation, output sanitisation, rate limiting, and comprehensive decision logging.

## References and Further Learning

The room recommends exploring:

- **MITRE ATLAS:** the technique catalogue, case studies, and mitigations.
- **OWASP AI Exchange:** broader AI security guidance, including agentic AI and non-LLM systems.

---

