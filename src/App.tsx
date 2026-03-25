/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, FormEvent } from "react";
import { Search, Loader2, Printer, ShieldAlert, FileText, AlertCircle, Mail, Copy, Check } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

export default function App() {
  const [cveId, setCveId] = useState("");
  const [loading, setLoading] = useState(false);
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSearch = async (e: FormEvent) => {
    e.preventDefault();
    if (!cveId.trim()) return;

    setLoading(true);
    setError(null);
    setReportHtml(null);

    try {
      const response = await fetch("/api/generate-cti", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cveId: cveId.trim().toUpperCase() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Error al generar el reporte");
      }

      setReportHtml(data.html);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleCopyEmail = async () => {
    if (!reportHtml) return;

    try {
      const type = "text/html";
      const blob = new Blob([reportHtml], { type });
      const data = [new ClipboardItem({ [type]: blob })];
      await navigator.clipboard.write(data);
      
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Error al copiar HTML:", err);
      // Fallback to simple text copy if ClipboardItem fails
      try {
        await navigator.clipboard.writeText(reportHtml);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (fallbackErr) {
        alert("No se pudo copiar el contenido. Intenta seleccionarlo manualmente.");
      }
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900 selection:bg-blue-100">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 py-6 px-4 no-print">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-2 rounded-lg shadow-lg shadow-blue-200">
              <ShieldAlert className="text-white w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">CTI Flash Engine</h1>
              <p className="text-xs text-slate-500 font-medium uppercase tracking-widest">AI-Powered Search Intelligence</p>
            </div>
          </div>
          <div className="hidden sm:block text-right">
            <p className="text-xs text-slate-400">v1.1.0 Stable</p>
            <p className="text-xs font-mono text-slate-400">Powered by Gemini 3 Flash</p>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-12">
        {/* Search Section */}
        <section className="mb-12 no-print">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-slate-900 mb-2">Análisis de Vulnerabilidades</h2>
            <p className="text-slate-600">Ingresa un ID de CVE para generar un reporte de inteligencia basado en búsqueda web en tiempo real.</p>
          </div>

          <form onSubmit={handleSearch} className="relative max-w-2xl mx-auto">
            <div className="relative group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Search className="h-5 w-5 text-slate-400 group-focus-within:text-blue-500 transition-colors" />
              </div>
              <input
                type="text"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                placeholder="Ej: CVE-2024-21408"
                className="block w-full pl-12 pr-32 py-4 bg-white border border-slate-200 rounded-2xl shadow-sm focus:ring-4 focus:ring-blue-100 focus:border-blue-500 transition-all outline-none text-lg font-medium"
                required
              />
              <button
                type="submit"
                disabled={loading}
                className="absolute inset-y-2 right-2 px-6 bg-blue-600 text-white rounded-xl font-semibold hover:bg-blue-700 active:scale-95 transition-all disabled:opacity-50 disabled:pointer-events-none flex items-center gap-2"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Analizar"}
              </button>
            </div>
          </form>
        </section>

        {/* Error State */}
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="bg-red-50 border border-red-200 p-4 rounded-xl flex items-start gap-3 mb-8 no-print"
            >
              <AlertCircle className="w-5 h-5 text-red-500 mt-0.5" />
              <div>
                <h3 className="text-red-800 font-bold">Error en la solicitud</h3>
                <p className="text-red-700 text-sm">{error}</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Loading State */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center justify-center py-20 no-print"
            >
              <div className="relative">
                <Loader2 className="w-16 h-16 text-blue-600 animate-spin" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <FileText className="w-6 h-6 text-blue-400" />
                </div>
              </div>
              <h3 className="mt-6 text-xl font-bold text-slate-900">Generando Reporte CTI...</h3>
              <p className="text-slate-500 mt-2 animate-pulse">Realizando búsqueda y procesando con IA</p>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Report Result */}
        <AnimatePresence>
          {reportHtml && !loading && (
            <motion.div
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="relative"
            >
              <div className="absolute -top-14 right-0 no-print flex gap-3">
                <button
                  onClick={handleCopyEmail}
                  className={`flex items-center gap-2 px-4 py-2 border rounded-lg shadow-sm transition-all font-medium ${
                    copied 
                      ? "bg-green-50 border-green-200 text-green-700" 
                      : "bg-white border-slate-200 text-slate-700 hover:bg-slate-50"
                  }`}
                >
                  {copied ? <Check className="w-4 h-4" /> : <Mail className="w-4 h-4" />}
                  {copied ? "¡Copiado!" : "Copiar para Email"}
                </button>
                <button
                  onClick={handlePrint}
                  className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg shadow-sm hover:bg-slate-50 transition-colors font-medium text-slate-700"
                >
                  <Printer className="w-4 h-4" />
                  Exportar PDF / Imprimir
                </button>
              </div>

              <div className="bg-white rounded-3xl shadow-2xl shadow-slate-200 border border-slate-100 p-8 sm:p-12 overflow-hidden">
                <div 
                  className="cti-report"
                  dangerouslySetInnerHTML={{ __html: reportHtml }}
                />
                
                <div className="mt-12 pt-8 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between gap-4 text-slate-400 text-sm no-print">
                  <p>© 2026 CTI Flash Engine - Generado automáticamente</p>
                  <div className="flex items-center gap-4">
                    <span>MSRC v2.0</span>
                    <span>Gemini 1.5 Flash</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Empty State */}
        {!reportHtml && !loading && !error && (
          <div className="text-center py-20 opacity-20 no-print">
            <FileText className="w-24 h-24 mx-auto mb-4" />
            <p className="text-xl font-medium">Esperando identificador CVE...</p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="py-12 text-center text-slate-400 text-xs no-print">
        <p>Herramienta diseñada para analistas de seguridad y equipos de respuesta ante incidentes.</p>
        <p className="mt-1">Los datos provienen de fuentes oficiales de Microsoft y son procesados por modelos de lenguaje de gran escala.</p>
      </footer>
    </div>
  );
}
