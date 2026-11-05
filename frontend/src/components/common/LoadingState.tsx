import { Spinner } from "@/components/common/Spinner";
import { cn } from "@/lib/utils";

interface LoadingStateProps {
  label?: string;
  className?: string;
}

export function LoadingState({ label = "Loading…", className }: LoadingStateProps) {
  return (
    <div
      className={cn("flex flex-col items-center justify-center gap-3 py-16", className)}
      role="status"
      aria-live="polite"
    >
      <Spinner />
      <p className="text-sm text-muted-foreground">{label}</p>
    </div>
  );
}
