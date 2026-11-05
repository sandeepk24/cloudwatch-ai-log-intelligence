import { useId, useMemo } from "react";
import { cn } from "@/lib/utils";
import type { TimeSeriesPoint } from "@/types/ops";

interface SeriesConfig {
  key: string;
  label: string;
  data: TimeSeriesPoint[];
  color: string;
}

interface TimeSeriesChartProps {
  series: SeriesConfig[];
  height?: number;
  className?: string;
  ariaLabel?: string;
}

export function TimeSeriesChart({
  series,
  height = 200,
  className,
  ariaLabel = "Time series chart",
}: TimeSeriesChartProps) {
  const gradId = useId();
  const width = 640;
  const pad = { t: 12, r: 12, b: 28, l: 40 };
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;

  const { paths, yMax, xLabels } = useMemo(() => {
    const allValues = series.flatMap((s) => s.data.map((p) => p.value));
    const max = Math.max(1, ...allValues);
    const longest = series.reduce((a, b) => (a.data.length >= b.data.length ? a : b), series[0]);
    const n = longest?.data.length ?? 0;

    const built = series.map((s) => {
      const pts = s.data.map((p, i) => {
        const x = pad.l + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
        const y = pad.t + innerH - (p.value / max) * innerH;
        return `${x},${y}`;
      });
      return { ...s, d: pts.length ? `M ${pts.join(" L ")}` : "" };
    });

    const labels =
      longest?.data
        .filter((_, i) => i % Math.ceil(n / 5) === 0 || i === n - 1)
        .map((p) => ({
          t: new Date(p.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        })) ?? [];

    return { paths: built, yMax: max, xLabels: labels };
  }, [series, innerH, innerW, pad.l, pad.t]);

  if (!series.length || !series.some((s) => s.data.length)) {
    return (
      <div className={cn("text-sm text-muted-foreground", className)} role="img" aria-label="No data">
        No series data
      </div>
    );
  }

  return (
    <figure className={cn("w-full", className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full max-h-[280px]"
        role="img"
        aria-label={ariaLabel}
      >
        <defs>
          <linearGradient id={gradId} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--color-primary)" stopOpacity="0.25" />
            <stop offset="100%" stopColor="var(--color-primary)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <line
            key={f}
            x1={pad.l}
            x2={width - pad.r}
            y1={pad.t + innerH * (1 - f)}
            y2={pad.t + innerH * (1 - f)}
            stroke="var(--color-border)"
            strokeDasharray="4 4"
          />
        ))}
        {paths.map((s) =>
          s.d ? (
            <g key={s.key}>
              <path d={s.d} fill="none" stroke={s.color} strokeWidth={2} vectorEffect="non-scaling-stroke" />
            </g>
          ) : null
        )}
        <text x={pad.l} y={height - 8} className="fill-muted-foreground text-[10px]">
          {xLabels[0]?.t}
        </text>
        <text
          x={width - pad.r}
          y={height - 8}
          textAnchor="end"
          className="fill-muted-foreground text-[10px]"
        >
          {xLabels[xLabels.length - 1]?.t}
        </text>
        <text x={4} y={pad.t + 4} className="fill-muted-foreground text-[10px]">
          {yMax}
        </text>
      </svg>
      <figcaption className="mt-2 flex flex-wrap gap-4 text-xs text-muted-foreground">
        {series.map((s) => (
          <span key={s.key} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ background: s.color }} aria-hidden />
            {s.label}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}
