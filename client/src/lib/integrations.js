import { FolderOpen, ShieldAlert, SquareTerminal } from "lucide-react";
import {
  SiAnthropic,
  SiConfluence,
  SiGithub,
  SiGitlab,
  SiGooglecloud,
  SiGooglegemini,
  SiJira,
  SiNotion,
  SiOpenai,
  SiQualys,
} from "react-icons/si";
import { FaAws, FaMicrosoft } from "react-icons/fa6";
import CrowdStrikeIcon from "../components/icons/CrowdStrikeIcon";

export const CATEGORIES = [
  { id: "ai_models", label: "AI Models" },
  { id: "cloud", label: "Cloud Providers" },
  { id: "vcs", label: "Version Control" },
  { id: "ticketing", label: "Ticketing" },
  { id: "knowledge", label: "Knowledge Sources" },
  { id: "endpoint", label: "Endpoint Security" },
  { id: "vuln_data", label: "Vulnerability Data" },
];

export const PROVIDERS = [
  {
    id: "gemini",
    label: "Gemini",
    category: "ai_models",
    icon: SiGooglegemini,
    blurb: "Google AI API key — required for any Gemini-backed agent.",
    fields: [
      { name: "GOOGLE_API_KEY", label: "API key", type: "password", required: true },
    ],
  },
  {
    id: "anthropic",
    label: "Anthropic",
    category: "ai_models",
    icon: SiAnthropic,
    blurb: "API key — needed if any agent is set to a Claude model in Settings.",
    fields: [
      { name: "ANTHROPIC_API_KEY", label: "API key", type: "password", required: true },
    ],
  },
  {
    id: "openai",
    label: "OpenAI",
    category: "ai_models",
    icon: SiOpenai,
    blurb: "API key — needed if any agent is set to a GPT model in Settings.",
    fields: [
      { name: "OPENAI_API_KEY", label: "API key", type: "password", required: true },
    ],
  },
  {
    id: "gcp",
    label: "Google Cloud",
    category: "cloud",
    icon: SiGooglecloud,
    blurb: "Service account credentials for cloud compliance checks.",
    fields: [
      {
        name: "GOOGLE_APPLICATION_CREDENTIALS",
        label: "Service account JSON path",
        type: "text",
        required: true,
        placeholder: "/path/to/sa.json",
      },
      {
        name: "GOOGLE_CLOUD_PROJECT",
        label: "Project ID",
        type: "text",
        required: true,
        placeholder: "my-project",
      },
    ],
  },
  {
    id: "aws",
    label: "AWS",
    category: "cloud",
    icon: FaAws,
    blurb: "IAM credentials for AWS resource & posture checks.",
    fields: [
      { name: "AWS_ACCESS_KEY_ID", label: "Access key ID", type: "text", required: true },
      {
        name: "AWS_SECRET_ACCESS_KEY",
        label: "Secret access key",
        type: "password",
        required: true,
      },
      { name: "AWS_REGION", label: "Region", type: "text", placeholder: "us-east-1" },
    ],
  },
  {
    id: "azure",
    label: "Azure",
    category: "cloud",
    icon: FaMicrosoft,
    blurb: "Service principal for Azure subscription checks.",
    fields: [
      { name: "AZURE_TENANT_ID", label: "Tenant ID", type: "text", required: true },
      { name: "AZURE_CLIENT_ID", label: "Client ID", type: "text", required: true },
      {
        name: "AZURE_CLIENT_SECRET",
        label: "Client secret",
        type: "password",
        required: true,
      },
      { name: "AZURE_SUBSCRIPTION_ID", label: "Subscription ID", type: "text" },
    ],
  },
  {
    id: "github",
    label: "GitHub",
    category: "vcs",
    icon: SiGithub,
    blurb: "Token for code review on pull requests.",
    fields: [
      { name: "GITHUB_TOKEN", label: "Personal access token", type: "password", required: true },
    ],
  },
  {
    id: "gitlab",
    label: "GitLab",
    category: "vcs",
    icon: SiGitlab,
    blurb: "Token for code review on merge requests.",
    fields: [
      {
        name: "GITLAB_URL",
        label: "Instance URL",
        type: "text",
        placeholder: "https://gitlab.com",
      },
      {
        name: "GITLAB_TOKEN",
        label: "Personal access token",
        type: "password",
        required: true,
      },
    ],
  },
  {
    id: "jira",
    label: "Jira",
    category: "ticketing",
    icon: SiJira,
    blurb: "Atlassian credentials for ticket creation.",
    fields: [
      { name: "JIRA_URL", label: "Site URL", type: "text", required: true, placeholder: "https://acme.atlassian.net" },
      { name: "JIRA_USER", label: "User email", type: "text", required: true },
      { name: "JIRA_TOKEN", label: "API token", type: "password", required: true },
    ],
  },
  {
    id: "confluence",
    label: "Confluence",
    category: "knowledge",
    icon: SiConfluence,
    blurb: "Cloud Confluence — the policy agent uses it to answer policy questions and summarize pages.",
    fields: [
      {
        name: "CONFLUENCE_URL",
        label: "Site URL",
        type: "text",
        required: true,
        placeholder: "https://acme.atlassian.net",
      },
      { name: "CONFLUENCE_USER", label: "User email", type: "text", required: true },
      { name: "CONFLUENCE_TOKEN", label: "API token", type: "password", required: true },
    ],
  },
  {
    id: "notion",
    label: "Notion",
    category: "knowledge",
    icon: SiNotion,
    blurb: "Notion workspace — search and summarize policy/runbook pages. Requires an internal-integration secret.",
    fields: [
      { name: "NOTION_TOKEN", label: "Internal integration token", type: "password", required: true },
    ],
  },
  {
    id: "local_docs",
    label: "Local docs",
    category: "knowledge",
    icon: FolderOpen,
    blurb: "Read .md/.txt/.pdf/.docx from a directory on disk. Useful for repo-vendored policies (e.g. ./policies/).",
    fields: [
      {
        name: "LOCAL_DOCS_PATH",
        label: "Directory path",
        type: "text",
        required: true,
        placeholder: "/path/to/policies",
      },
    ],
  },
  {
    id: "crowdstrike",
    label: "CrowdStrike Falcon",
    category: "endpoint",
    icon: CrowdStrikeIcon,
    blurb: "Falcon API client credentials — gives the Endpoint Security agent access to hosts, detections, and incidents.",
    fields: [
      { name: "FALCON_CLIENT_ID", label: "Client ID", type: "text", required: true },
      { name: "FALCON_CLIENT_SECRET", label: "Client secret", type: "password", required: true },
      {
        name: "FALCON_BASE_URL",
        label: "API base URL",
        type: "text",
        placeholder: "https://api.crowdstrike.com",
      },
    ],
  },
  {
    id: "qualys",
    label: "Qualys VM",
    category: "endpoint",
    icon: SiQualys,
    blurb: "Qualys VM API credentials — host inventory and vulnerability findings.",
    fields: [
      { name: "QUALYS_USERNAME", label: "Username", type: "text", required: true },
      { name: "QUALYS_PASSWORD", label: "Password", type: "password", required: true },
      {
        name: "QUALYS_BASE_URL",
        label: "Platform URL",
        type: "text",
        required: true,
        placeholder: "https://qualysapi.qualys.com",
      },
    ],
  },
  {
    id: "nvd",
    label: "NVD",
    category: "vuln_data",
    icon: ShieldAlert,
    blurb: "API key for vulnerability triage lookups.",
    fields: [
      { name: "NVD_API_KEY", label: "API key", type: "password", required: true },
    ],
  },
];

const CATEGORY_LABELS = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.label]));
export const labelForCategory = (id) => CATEGORY_LABELS[id] || id;
export const providersInCategory = (catId) =>
  PROVIDERS.filter((p) => p.category === catId);

export const PROVIDERS_BY_ID = Object.fromEntries(PROVIDERS.map((p) => [p.id, p]));

export const getProvider = (id) => PROVIDERS_BY_ID[id] || {
  id,
  label: id,
  icon: SquareTerminal,
  blurb: "",
  fields: [],
};
