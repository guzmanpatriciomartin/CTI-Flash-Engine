import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import axios from "axios";
import { GoogleGenAI } from "@google/genai";
import MarkdownIt from "markdown-it";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const md = new MarkdownIt({
  html: true,
  linkify: true,
  typographer: true,
});

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());
  app.use(cors());

  // API Route for CTI Generation
  app.post("/api/generate-cti", async (req, res) => {
    const { cveId } = req.body;

    if (!cveId || !cveId.match(/^CVE-\d{4}-\d{4,7}$/i)) {
      return res.status(400).json({ error: "ID de CVE inválido. Formato: CVE-YYYY-XXXX" });
    }

    try {
      // 1. Generate CTI Report with Gemini using Google Search
      const geminiApiKey = process.env.GEMINI_API_KEY;
      if (!geminiApiKey) {
        return res.status(500).json({ error: "GEMINI_API_KEY no configurada." });
      }

      const ai = new GoogleGenAI({ apiKey: geminiApiKey });

      const systemPrompt = `
        Eres un Analista Senior de Inteligencia de Amenazas (CTI).
        Tu tarea es investigar y sintetizar información sobre una vulnerabilidad específica (CVE) utilizando búsqueda en tiempo real.
        
        REGLAS CRÍTICAS:
        - El reporte DEBE estar estrictamente en ESPAÑOL.
        - Usa un tono profesional, técnico y directo.
        - Utiliza Google Search para obtener los datos más recientes y precisos (incluyendo CISA KEV, NVD, MITRE y avisos de proveedores).
        
        ESTRUCTURA DE SALIDA OBLIGATORIA (Markdown):
        
        # Alerta CTI – [CVE-ID]

        ---

        ## Resumen Ejecutivo
        Breve descripción de la vulnerabilidad, indicando el componente afectado, tipo de falla y nivel de riesgo.
        Nota: Indica explícitamente si se encuentra o no en el catálogo CISA KEV.

        ---

        ## Impacto
        - Tipo de impacto: (RCE / Elevación de privilegios / DoS / Divulgación de información / etc.)
        - Vector de ataque: Local / Remoto
        - Privilegios requeridos: Ninguno / Bajo / Alto
        - Interacción del usuario: Sí / No
        - Alcance: Cambiado / No cambiado

        ---

        ## Severidad
        - CVSS v3.1 Base Score: X.X (Crítica / Alta / Media / Baja)
        - Vector CVSS: CVSS:3.1/...
        - Fuente: [NVD / Vendor / etc.]

        ---

        ## Matriz de Riesgo CVSS v3.1
        | Producto | Componente | Protocolo | ¿Explotable remotamente sin autenticación? | Puntaje Base | Vector de Ataque | Complejidad del Ataque | Privilegios Requeridos | Interacción del Usuario | Alcance | Confidencialidad | Integridad | Disponibilidad |
        |----------|-----------|-----------|--------------------------------------------|--------------|------------------|------------------------|------------------------|------------------------|---------|------------------|------------|----------------|
        | [Producto] | [Componente] | [Protocolo] | Sí / No | X.X | Red / Local | Baja / Alta | Ninguno / Bajo / Alto | Ninguna / Requerida | Sin cambio / Cambiado | Ninguno / Bajo / Alto | Ninguno / Bajo / Alto | Ninguno / Bajo / Alto |

        ---

        ## Debilidad
        Descripción detallada de la vulnerabilidad:
        - Tipo de vulnerabilidad (ej. deserialización, type confusion, etc.)
        - Componente afectado
        - Condiciones de explotación
        - Resultado de explotación
        - CWE-XXX: [Nombre de la debilidad]

        ---

        ## Información General
        - CVE: [CVE-ID]
        - Proveedor: [Vendor]
        - Producto(s): [Productos afectados]
        - Tipo: Vulnerabilidad de Seguridad
        - Fecha de publicación: [Fecha]
        - Última actualización: [Fecha]
        - Fuente: Advisory oficial / NVD

        ---

        ## Productos Afectados
        | Producto | Versiones afectadas |
        |----------|-------------------|
        | [Producto 1] | [Versiones] |
        | [Producto 2] | [Versiones] |

        ---

        ## Parches y Mitigación
        - Estado del parche: Disponible / No disponible
        - Acción requerida: Aplicar actualizaciones de seguridad del proveedor
        Mitigaciones adicionales:
        - [Lista de mitigaciones]

        ---

        ## Explotación en la Naturaleza
        - Explotación activa: Sí / No / Desconocido
        - Incluido en KEV: Sí / No
        - Fecha de inclusión KEV: [Fecha o N/A]
        - Observaciones: [Detalles adicionales]

        ---

        ## Referencias
        - [Lista de URLs de Advisory, NVD, MITRE, CISA KEV]

        ---

        ## Observaciones CTI
        - Posible abuso en campañas reales
        - Técnicas MITRE ATT&CK relacionadas
        - Relevancia para la organización
      `;

      const result = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [{ role: "user", parts: [{ text: `Realiza un análisis CTI completo para la vulnerabilidad ${cveId}.` }] }],
        config: {
          systemInstruction: systemPrompt,
          temperature: 0.2,
          tools: [{ googleSearch: {} }],
        },
      });

      const markdownReport = result.text || "No se pudo generar el reporte.";
      
      // 3. Convert Markdown to HTML
      const htmlReport = md.render(markdownReport);

      res.json({ html: htmlReport, markdown: markdownReport });
    } catch (error: any) {
      console.error("Error generating CTI:", error);
      res.status(500).json({ error: "Error interno al procesar el reporte: " + error.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
