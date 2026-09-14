from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


Status = Literal["observed", "inferred", "unavailable"]


class ReportField(BaseModel):
    label: str
    value: Any = None
    status: Status
    evidence: Optional[str] = None


class ReportFinding(BaseModel):
    title: str
    category: str
    severity: str
    status: Status
    evidence: str
    explanation: str
    recommendation: str


class ReportSection(BaseModel):
    title: str
    summary: Optional[str] = None
    fields: List[ReportField] = Field(default_factory=list)
    findings: List[ReportFinding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class ReportDocument(BaseModel):
    report_type: Literal["executive", "technical"]
    title: str
    capture_id: str
    sections: List[ReportSection]
    limitations: List[str] = Field(default_factory=list)
    markdown: str = ""


class ReportBundle(BaseModel):
    executive: ReportDocument
    technical: ReportDocument

    def as_markdown_files(self) -> Dict[str, str]:
        return {
            "executive.md": self.executive.markdown,
            "technical.md": self.technical.markdown,
        }
