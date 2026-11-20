import React, { InputHTMLAttributes } from "react";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helper?: string;
}

export function Input({ label, error, helper, id, className = "", ...props }: InputProps) {
  const inputId = id || props.name;

  return (
    <div className="flex flex-col gap-1.5 w-full">
      {label && (
        <label htmlFor={inputId} className="text-xs font-medium text-slate-300">
          {label}
        </label>
      )}
      <input
        id={inputId}
        className={`w-full px-3 py-2 bg-slate-950/80 border ${
          error ? "border-rose-500 focus:ring-rose-500" : "border-slate-800 focus:border-emerald-500 focus:ring-emerald-500"
        } rounded-lg text-sm text-slate-100 placeholder-slate-500 transition-colors focus:outline-none focus:ring-1 disabled:opacity-50 ${className}`}
        {...props}
      />
      {error && <p className="text-xs text-rose-400 mt-0.5">{error}</p>}
      {helper && !error && <p className="text-xs text-slate-500 mt-0.5">{helper}</p>}
    </div>
  );
}
