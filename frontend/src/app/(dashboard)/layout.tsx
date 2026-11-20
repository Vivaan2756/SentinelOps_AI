"use client";

import React, { Suspense, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";

function LoadingFallback() {
  return (
    <div className="flex h-48 w-full items-center justify-center text-slate-500">
      <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { user, token, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && (!token || !user)) {
      router.replace("/login");
    }
  }, [user, token, isLoading, router]);

  const showLoadingOverlay = isLoading || (!token && !user);

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      {/* Fixed Left Navigation Sidebar */}
      <Suspense fallback={<aside className="w-64 bg-slate-950 border-r border-slate-800/80" />}>
        <Sidebar />
      </Suspense>

      {/* Main View Area */}
      <div className="flex-1 flex flex-col min-w-0 relative">
        <Topbar />
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          <Suspense fallback={<LoadingFallback />}>
            {children}
          </Suspense>
        </main>

        {/* Auth Validation Overlay (never drops children segment from render tree) */}
        {showLoadingOverlay && (
          <div className="absolute inset-0 z-50 flex items-center justify-center bg-slate-950/95 backdrop-blur-sm text-slate-400">
            <div className="flex flex-col items-center gap-3">
              <div className="w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-xs font-mono">Loading Workspace Context...</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
