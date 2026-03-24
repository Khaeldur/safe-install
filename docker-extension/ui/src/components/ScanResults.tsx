import React, { useState } from "react";
import {
  Box,
  Typography,
  Chip,
  Paper,
  Alert,
  Collapse,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Divider,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";

interface ScanResultsProps {
  result: {
    error?: string;
    severity?: string;
    findings?: any[];
    typosquat?: { is_typosquat?: boolean; warnings?: any[] };
    intelligence?: any[];
    deps?: any[];
    package?: string;
    total?: number;
  };
}

const SEVERITY_COLORS: Record<string, "error" | "warning" | "info" | "success" | "default"> = {
  CRITICAL: "error",
  HIGH: "warning",
  MEDIUM: "info",
  LOW: "default",
  CLEAN: "success",
};

export function ScanResults({ result }: ScanResultsProps) {
  const [expandedItems, setExpandedItems] = useState<Set<number>>(new Set());

  if (result.error) {
    return <Alert severity="error">{result.error}</Alert>;
  }

  const severity = result.severity || "CLEAN";
  const findings = result.findings || [];
  const isClean = severity === "CLEAN" && findings.length === 0;

  const toggleExpand = (index: number) => {
    setExpandedItems((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  };

  return (
    <Paper sx={{ p: 2 }}>
      {/* Summary header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        {isClean ? (
          <CheckCircleIcon color="success" sx={{ fontSize: 32 }} />
        ) : (
          <WarningIcon color={severity === "CRITICAL" ? "error" : "warning"} sx={{ fontSize: 32 }} />
        )}
        <Box>
          <Typography variant="h6">
            {result.package ? `Scan: ${result.package}` : "Scan Results"}
          </Typography>
          <Box sx={{ display: "flex", gap: 1, mt: 0.5 }}>
            <Chip
              label={severity}
              color={SEVERITY_COLORS[severity] || "default"}
              size="small"
            />
            <Chip
              label={`${findings.length} finding${findings.length !== 1 ? "s" : ""}`}
              size="small"
              variant="outlined"
            />
          </Box>
        </Box>
      </Box>

      {/* Typosquat warning */}
      {result.typosquat?.is_typosquat && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Possible typosquat detected!
          {result.typosquat.warnings?.map((w: any, i: number) => (
            <Typography key={i} variant="body2">
              Did you mean <strong>{w.popular}</strong>? (distance: {w.distance})
            </Typography>
          ))}
        </Alert>
      )}

      {/* Intelligence warnings */}
      {result.intelligence && result.intelligence.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="subtitle2">Intelligence</Typography>
          {result.intelligence.map((w: any, i: number) => (
            <Typography key={i} variant="body2">
              [{w.level}] {w.message}
            </Typography>
          ))}
        </Alert>
      )}

      {/* Findings list */}
      {findings.length > 0 ? (
        <List disablePadding>
          {findings.map((finding, i) => (
            <React.Fragment key={i}>
              {i > 0 && <Divider />}
              <ListItem
                sx={{ px: 0, cursor: "pointer" }}
                onClick={() => toggleExpand(i)}
                secondaryAction={
                  <IconButton size="small">
                    {expandedItems.has(i) ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  </IconButton>
                }
              >
                <ListItemText
                  primary={
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Chip
                        label={finding.severity || finding.pattern || "FINDING"}
                        color={SEVERITY_COLORS[finding.severity] || "default"}
                        size="small"
                      />
                      <Typography variant="body2">
                        {finding.pattern || finding.description || finding.rule || `Finding #${i + 1}`}
                      </Typography>
                      {finding.line && (
                        <Typography variant="caption" color="text.secondary">
                          line {finding.line}
                        </Typography>
                      )}
                    </Box>
                  }
                />
              </ListItem>
              <Collapse in={expandedItems.has(i)}>
                <Box sx={{ pl: 2, pb: 2, fontFamily: "monospace", fontSize: "0.85rem" }}>
                  {finding.context && (
                    <Paper variant="outlined" sx={{ p: 1, mb: 1, bgcolor: "grey.50" }}>
                      <code>{finding.context}</code>
                    </Paper>
                  )}
                  {finding.file && (
                    <Typography variant="caption" display="block">
                      File: {finding.file}
                    </Typography>
                  )}
                  {finding.recommendation && (
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                      {finding.recommendation}
                    </Typography>
                  )}
                </Box>
              </Collapse>
            </React.Fragment>
          ))}
        </List>
      ) : (
        isClean && (
          <Alert severity="success" icon={<CheckCircleIcon />}>
            No suspicious patterns detected.
          </Alert>
        )
      )}

      {/* Dependencies */}
      {result.deps && result.deps.length > 0 && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            Layers / Dependencies ({result.deps.length})
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
            {result.deps.map((dep: any, i: number) => (
              <Chip
                key={i}
                label={`${dep.name}${dep.version ? "@" + dep.version : ""}`}
                size="small"
                variant={dep.direct ? "filled" : "outlined"}
              />
            ))}
          </Box>
        </Box>
      )}
    </Paper>
  );
}
