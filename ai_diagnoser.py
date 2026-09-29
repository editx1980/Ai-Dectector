from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal, Protocol, cast

from google import genai
from google.genai import types
from pydantic import BaseModel, Field


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

EVIDENCE_FILE = LOG_FOLDER / "evidence.jsonl"
DIAGNOSES_FILE = LOG_FOLDER / "diagnoses.jsonl"

MODEL_NAME = "gemini-3.5-flash-lite"

JsonObject = dict[str, object]


class ModelsAPI(Protocol):
    def generate_content(
        self,
        *,
        model: str,
        contents: str,
        config: types.GenerateContentConfig | None = None,
    ) -> types.GenerateContentResponse:
        ...


class Diagnosis(BaseModel):
    status: Literal["NO_TESTS", "FAILED", "PASSED", "UNKNOWN"] = Field(
        description="The test status from the evidence."
    )
    diagnosis: str = Field(
        description="A concise explanation of what the evidence indicates."
    )
    likely_cause: str = Field(
        description="The most likely cause based only on the supplied evidence."
    )
    file: str | None = Field(
        description="The file most directly associated with the problem, if known."
    )
    line: int | None = Field(
        description="The relevant source-code line number, if known."
    )
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        description="Confidence in the diagnosis based on the available evidence."
    )
    evidence: list[str] = Field(
        description="Specific pieces of evidence supporting the diagnosis."
    )
    next_step: str = Field(
        description="The next investigation or debugging step the developer should take."
    )


def to_json_object(value: object) -> JsonObject | None:
    if not isinstance(value, dict):
        return None

    object_value = cast(dict[object, object], value)

    for key in object_value:
        if not isinstance(key, str):
            return None

    return cast(JsonObject, value)


def load_evidence() -> list[JsonObject]:
    if not EVIDENCE_FILE.exists():
        return []

    evidence: list[JsonObject] = []

    with EVIDENCE_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                value: object = json.loads(line)
            except json.JSONDecodeError:
                continue

            record = to_json_object(value)

            if record is not None:
                evidence.append(record)

    return evidence


def get_object(
    record: JsonObject,
    key: str,
) -> JsonObject | None:
    value = record.get(key)
    return to_json_object(value)


def get_string(
    record: JsonObject,
    key: str,
) -> str | None:
    value = record.get(key)

    if isinstance(value, str):
        return value

    return None


def get_int(
    record: JsonObject,
    key: str,
) -> int | None:
    value = record.get(key)

    if isinstance(value, int) and not isinstance(value, bool):
        return value

    return None


def get_test_status(
    evidence: JsonObject,
) -> str | None:
    test = get_object(
        evidence,
        "test",
    )

    if test is None:
        return None

    return get_string(
        test,
        "status",
    )


def build_prompt(
    evidence: JsonObject,
) -> str:
    evidence_json = json.dumps(
        evidence,
        indent=2,
        ensure_ascii=False,
    )

    return f"""
You are the AI Developer Overseer.

Your job is to diagnose a software problem using ONLY the supplied evidence.

Do not invent files, line numbers, errors, causes, or events that are not
supported by the evidence.

Distinguish clearly between confirmed facts and likely causes.

If the evidence is insufficient to identify a cause, say so and use LOW
confidence.

The developer wants useful debugging guidance, not a code rewrite.

Analyze this complete evidence record:

{evidence_json}

Return a structured diagnosis containing:

- the test status
- what happened
- the most likely cause
- the affected file if known
- the affected line if known
- confidence
- concrete evidence supporting the diagnosis
- the next debugging step
""".strip()


def diagnose_evidence(
    client: genai.Client,
    evidence: JsonObject,
) -> Diagnosis:
    prompt = build_prompt(evidence)

    models = cast(
        ModelsAPI,
        client.models,
    )

    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=Diagnosis,
    )

    response = models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=config,
    )

    parsed = response.parsed

    if isinstance(parsed, Diagnosis):
        return parsed

    if isinstance(parsed, dict):
        return Diagnosis.model_validate(parsed)

    raise RuntimeError(
        "Gemini returned an unexpected response type."
    )


def write_diagnosis(
    evidence: JsonObject,
    diagnosis: Diagnosis,
) -> None:
    DIAGNOSES_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    record: JsonObject = {
        "timestamp": get_string(
            evidence,
            "timestamp",
        ),
        "test_status": get_test_status(
            evidence,
        ),
        "diagnosis": diagnosis.model_dump(),
    }

    with DIAGNOSES_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )


def print_diagnosis(
    evidence_number: int,
    evidence: JsonObject,
    diagnosis: Diagnosis,
) -> None:
    timestamp = get_string(
        evidence,
        "timestamp",
    )

    print()
    print("=" * 50)
    print(f"Diagnosis #{evidence_number}")
    print("=" * 50)
    print(f"Time: {timestamp}")
    print(f"Status: {diagnosis.status}")
    print(f"Diagnosis: {diagnosis.diagnosis}")
    print(f"Likely cause: {diagnosis.likely_cause}")
    print(f"File: {diagnosis.file}")
    print(f"Line: {diagnosis.line}")
    print(f"Confidence: {diagnosis.confidence}")

    print("Evidence:")

    for item in diagnosis.evidence:
        print(f"  - {item}")

    print(f"Next step: {diagnosis.next_step}")


def main() -> None:
    print()
    print("=" * 50)
    print("AI DEVELOPER OVERSEER - AI DIAGNOSIS")
    print("=" * 50)

    api_key = os.getenv(
        "GEMINI_API_KEY"
    )

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY environment variable is not set."
        )

    evidence_records = load_evidence()

    if not evidence_records:
        print("No evidence records found.")
        return

    client = genai.Client(
        api_key=api_key,
    )

    for evidence_number, evidence in enumerate(
        evidence_records,
        start=1,
    ):
        status = get_test_status(
            evidence,
        )

        if status not in {
            "FAILED",
            "NO_TESTS",
        }:
            continue

        try:
            diagnosis = diagnose_evidence(
                client,
                evidence,
            )

            write_diagnosis(
                evidence,
                diagnosis,
            )

            print_diagnosis(
                evidence_number,
                evidence,
                diagnosis,
            )

        except Exception as error:
            print()
            print(
                f"Diagnosis #{evidence_number} failed."
            )
            print(
                f"Error: {error}"
            )

    print()
    print(
        f"Diagnosis file: {DIAGNOSES_FILE}"
    )


if __name__ == "__main__":
    main()