import React from "react";

export type BadgeVariant =
  | "healthy"
  | "degraded"
  | "unhealthy"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "recovered"
  | "detected"
  | "investigating"
  | "awaiting_approval"
  | "investigation_failed"
  | "remediating"
  | "verifying"
  | "closed"
  | "success"
  | "warning"
  | "error"
  | "info"
  | "neutral";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

export function Badge({ children, variant = "neutral", className = "" }: BadgeProps) {
  const styles: Record<BadgeVariant, string> = {
    healthy: "bg-emerald-950/60 text-emerald-400 border-emerald-800/80",
    success: "bg-emerald-950/60 text-emerald-400 border-emerald-800/80",
    recovered: "bg-emerald-950/60 text-emerald-400 border-emerald-800/80",
    degraded: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    warning: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    medium: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    investigating: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    awaiting_approval: "bg-cyan-950/60 text-cyan-400 border-cyan-800/80",
    investigation_failed: "bg-rose-950/60 text-rose-400 border-rose-800/80",
    remediating: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    unhealthy: "bg-rose-950/60 text-rose-400 border-rose-800/80",
    error: "bg-rose-950/60 text-rose-400 border-rose-800/80",
    detected: "bg-rose-950/60 text-rose-400 border-rose-800/80",
    critical: "bg-red-950/70 text-red-300 border-red-700 font-semibold",
    high: "bg-orange-950/60 text-orange-400 border-orange-800/80",
    info: "bg-blue-950/60 text-blue-400 border-blue-800/80",
    low: "bg-blue-950/60 text-blue-400 border-blue-800/80",
    verifying: "bg-cyan-950/60 text-cyan-400 border-cyan-800/80",
    closed: "bg-slate-800/70 text-slate-400 border-slate-700/80",
    neutral: "bg-slate-800/70 text-slate-300 border-slate-700/80",
  };

  const selected = (variant && styles[variant.toLowerCase() as BadgeVariant]) || styles.neutral;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${selected} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-75" />
      {children}
    </span>
  );
}
