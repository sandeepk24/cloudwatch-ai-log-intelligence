import type { ReactNode } from "react";

interface HeaderProps {
  title: string;
  description?: string;
  children?: ReactNode;
}

export function Header({ title, description, children }: HeaderProps) {
  return (
    <div className="flex items-start justify-between border-b border-border px-8 py-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {children && <div className="flex items-center gap-3">{children}</div>}
    </div>
  );
}
