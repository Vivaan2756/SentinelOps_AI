"use client";

import React, { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { ChevronDown, Building, User as UserIcon, LogOut } from "lucide-react";

export function Topbar() {
  const { user, activeWorkspace, workspaces, setActiveWorkspace, logout } = useAuth();
  const [isWsDropdownOpen, setIsWsDropdownOpen] = useState(false);

  return (
    <header className="h-14 bg-slate-950/80 backdrop-blur border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Workspace Selector */}
      <div className="relative">
        <button
          onClick={() => setIsWsDropdownOpen(!isWsDropdownOpen)}
          className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-200 hover:border-slate-700 transition-colors"
        >
          <Building className="w-3.5 h-3.5 text-emerald-400" />
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-100">
              {activeWorkspace?.workspace_name || "Select Workspace"}
            </span>
            {activeWorkspace?.role && (
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                {activeWorkspace.role}
              </span>
            )}
          </div>
          <ChevronDown className="w-3 h-3 text-slate-400" />
        </button>

        {/* Dropdown Menu */}
        {isWsDropdownOpen && (
          <>
            <div
              className="fixed inset-0 z-10"
              onClick={() => setIsWsDropdownOpen(false)}
            />
            <div className="absolute left-0 mt-2 w-64 bg-slate-900 border border-slate-800 rounded-xl shadow-xl p-1.5 z-20 space-y-1">
              <div className="px-2.5 py-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Assigned Workspaces
              </div>
              {workspaces.map((ws) => (
                <button
                  key={ws.workspace_id}
                  onClick={() => {
                    setActiveWorkspace(ws);
                    setIsWsDropdownOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs transition-colors ${
                    activeWorkspace?.workspace_id === ws.workspace_id
                      ? "bg-slate-800 text-emerald-400 font-semibold"
                      : "text-slate-300 hover:bg-slate-800/60"
                  }`}
                >
                  <span className="truncate">{ws.workspace_name}</span>
                  <span className="text-[10px] uppercase font-mono text-slate-400">
                    {ws.role}
                  </span>
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      {/* User and Session Context */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5 text-xs text-slate-300">
          <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
            <UserIcon className="w-3.5 h-3.5" />
          </div>
          <div className="hidden sm:block text-left">
            <div className="font-medium text-slate-200">{user?.full_name || user?.email}</div>
            <div className="text-[10px] text-slate-500 font-mono">{user?.email}</div>
          </div>
        </div>

        <button
          onClick={logout}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 transition-colors"
          title="Sign out of SentinelOps AI"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden md:inline">Sign Out</span>
        </button>
      </div>
    </header>
  );
}
