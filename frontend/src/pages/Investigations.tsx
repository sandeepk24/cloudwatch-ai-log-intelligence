import { Card, CardContent } from "@/components/common/Card";
import { Header } from "@/components/layout/Header";

export function Investigations() {
  return (
    <div>
      <Header
        title="Investigations"
        description="Incident timelines land after Logs Insights ingestion is wired."
      />
      <div className="p-8">
        <Card>
          <CardContent className="py-16 text-center text-sm text-muted-foreground">
            No CloudWatch query engine yet. This page is a placeholder so navigation and routing
            are in place before investigation data arrives.
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
