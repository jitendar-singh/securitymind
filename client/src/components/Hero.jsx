import { motion as Motion } from "framer-motion";
import { ShieldAlert, Cloud, GitPullRequestArrow, FileSearch } from "lucide-react";
import SuggestionChip from "./SuggestionChip";

const SUGGESTIONS = [
  {
    icon: ShieldAlert,
    label: "Threat-model my Django + RDS app",
    prompt:
      "Threat-model a Django web app deployed on AWS with an RDS Postgres database, OAuth login, and S3 for user uploads.",
  },
  {
    icon: Cloud,
    label: "Audit my GCP IAM and storage",
    prompt:
      "Audit my GCP project for IAM misconfigurations and publicly accessible storage buckets.",
  },
  {
    icon: GitPullRequestArrow,
    label: "Review this GitHub pull request",
    prompt:
      "Review this pull request: https://github.com/owner/repo/pull/123",
  },
  {
    icon: FileSearch,
    label: "Triage CVE-2024-3094",
    prompt: "Triage CVE-2024-3094 — what's the impact and fix?",
  },
];

export default function Hero({ onPick }) {
  return (
    <Motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: "easeOut" }}
      className="flex-1 grid place-items-center px-6 py-16"
    >
      <div className="text-center max-w-3xl">
        <h1 className="hero text-[var(--text-h)] mb-4">
          How can <span className="bg-gradient-to-r from-[var(--accent)] to-[var(--accent-h)] bg-clip-text text-transparent">Security Mind</span> help today?
        </h1>
        <p className="text-[var(--text-muted)] text-base sm:text-[17px]">
          Chat with your security posture management agent. Threat models,
          vulnerability triage, code review, cloud compliance — one prompt.
        </p>

        <div className="mt-10 flex flex-wrap justify-center gap-3">
          {SUGGESTIONS.map((s) => (
            <SuggestionChip key={s.label} {...s} onPick={onPick} />
          ))}
        </div>
      </div>
    </Motion.div>
  );
}
