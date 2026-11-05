import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "@/context/ThemeContext";
import { AppLayout } from "@/components/layout/AppLayout";
import { Overview } from "@/pages/Overview";
import { LogExplorer } from "@/pages/LogExplorer";
import { IncidentCenter } from "@/pages/IncidentCenter";
import { AIInvestigation } from "@/pages/AIInvestigation";
import { Trends } from "@/pages/Trends";
import { SettingsPage } from "@/pages/SettingsPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/logs" element={<LogExplorer />} />
              <Route path="/incidents" element={<IncidentCenter />} />
              <Route path="/investigation" element={<AIInvestigation />} />
              <Route path="/trends" element={<Trends />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/investigations" element={<Navigate to="/incidents" replace />} />
              <Route path="/dashboard" element={<Navigate to="/overview" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
