"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Server,
  AlertTriangle,
  BrainCircuit,
  ShieldCheck,
  BookOpen,
  CheckCircle2,
  FileBarChart,
  Settings,
  Activity,
} from "lucide-react";

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  disabled?: boolean;
}

const navItems: NavItem[] = [
  { label: "Overview", href: "/overview", icon: LayoutDashboard },
  { label: "Services & Monitoring", href: "/services", icon: Server },
  { label: "Incidents", href: "/incidents", icon: AlertTriangle },
  {
    label: "AI Investigation",
    href: "/investigations",
    icon: BrainCircuit,
    badge: "Phase 3",
  },
  {
    label: "Remediation & Approvals",
    href: "/remediation/approvals",
    icon: ShieldCheck,
    badge: "Phase 4",
  },
  {
    label: "Remediation Playbooks",
    href: "/playbooks",
    icon: BookOpen,
    badge: "Phase 4",
  },

  {
    label: "Verification & Recovery",
    href: "/verification",
    icon: CheckCircle2,
    badge: "Phase 4.3",
  },
  {
    label: "Reports & Analytics",
    href: "/analytics",
    icon: FileBarChart,
    badge: "SRE",
  },
  { label: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none">
      <div>
        {/* Brand Header */}
        <div className="p-5 flex items-center gap-3 border-b border-slate-800/80">
          <div className="w-8 h-8 rounded-lg bg-emerald-600/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="font-semibold text-sm text-slate-100 flex items-center gap-1.5">
              SentinelOps <span className="text-emerald-400">AI</span>
            </div>
            <div className="text-[10px] text-slate-400 tracking-wider uppercase font-mono">
              SRE Platform
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href || pathname?.startsWith(`${item.href}/`);

            if (item.disabled) {
              return (
                <div
                  key={item.label}
                  className="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-500 cursor-not-allowed hover:bg-slate-900/30"
                  title="Coming in later delivery phases per blueprint roadmap"
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4 opacity-50" />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="text-[10px] bg-slate-900 border border-slate-800 text-slate-500 px-1.5 py-0.2 rounded font-mono">
                      {item.badge}
                    </span>
                  )}
                </div>
              );
            }

            return (
              <Link
                key={item.label}
                href={item.href}
                className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                  isActive
                    ? "bg-slate-900 text-emerald-400 border border-slate-800 font-semibold"
                    : "text-slate-400 hover:text-slate-100 hover:bg-slate-900/60"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? "text-emerald-400" : "text-slate-400"}`} />
                  <span>{item.label}</span>
                </div>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-1">
        <div className="flex justify-between items-center text-slate-400">
          <span>Engine Status</span>
          <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Operational
          </span>
        </div>
        <div className="text-slate-400 font-mono text-[10px]">Version 0.3.0 • Phase 3 Agentic</div>
      </div>
    </aside>
  );
}
