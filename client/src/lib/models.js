// Model options surfaced in the Settings UI. Each provider exposes its two
// latest models. Gemini ids are sent to ADK directly; Claude/GPT ids are
// wrapped server-side with LiteLlm. Picking a non-Gemini model requires the
// matching API key integration (Anthropic / OpenAI) to be configured.
export const MODEL_GROUPS = [
  {
    provider: "Google",
    models: ["gemini-2.5-pro", "gemini-2.5-flash"],
  },
  {
    provider: "Anthropic",
    models: ["claude-opus-4-7", "claude-sonnet-4-6"],
  },
  {
    provider: "OpenAI",
    models: ["gpt-5", "gpt-5-mini"],
  },
];

export const AVAILABLE_MODELS = MODEL_GROUPS.flatMap((g) => g.models);

export const AGENT_LABELS = {
  secmind: "Master Agent",
  vuln_triage_agent: "Vulnerability Triage Agent",
  code_review_agent: "Code Review Agent",
  cloud_compliance_agent: "Cloud Compliance Agent",
  gcp_workload_security_agent: "GCP Workload Security Agent",
  endpoint_security_agent: "Endpoint Security Agent",
  threat_modeling_agent: "Threat Modeling Agent",
  policy_agent: "Policy Agent",
  jira_agent: "Jira Agent",
};

export const labelForAgent = (id) => AGENT_LABELS[id] || id;
