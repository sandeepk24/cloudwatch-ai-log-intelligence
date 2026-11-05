import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/common/Button";
import { cn } from "@/lib/utils";

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({ message, onRetry, className }: ErrorStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center rounded-lg border border-destructive/30 bg-destructive/5 px-6 py-12 text-center",
        className
      )}
      role="alert"
    >
      <AlertTriangle className="h-9 w-9 text-destructive" aria-hidden />
      <p className="mt-3 text-sm text-foreground">{message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}
