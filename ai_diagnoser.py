from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol, TypeAlias, cast

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from change_transaction import (
    TransactionLogError,
    get_transaction,
)


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

EVIDENCE_FILE = LOG_FOLDER / "evidence.jsonl"
CONTEXT_FILE = LOG_FOLDER / "project_context.jsonl"
DIAGNOSES_FILE = LOG_FOLDER / "diagnoses.jsonl"
CHANGE_TRANSACTIONS_FILE = LOG_FOLDER / "change_transactions.jsonl"

MODEL_NAME = "gemini-3.5-flash-lite"


JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)

JsonObject: TypeAlias = dict[str, JsonValue]


class ModelsAPI(Protocol):
    def generate_content(
        self,
        *,
        model: str,
        contents: str,
        config: types.GenerateContentConfig | None = None,
    ) -> types.GenerateContentResponse:
        ...


class ExactChange(BaseModel):
    file: str | None = Field(...)
    line: int | None = Field(...)
    old_text: str | None = Field(...)
    new_text: str | None = Field(...)


class Diagnosis(BaseModel):
    status: Literal[
        "NO_TESTS",
        "FAILED",
        "PASSED",
        "UNKNOWN",
    ] = Field(...)

    diagnosis: str = Field(...)
    likely_cause: str = Field(...)

    file: str | None = Field(...)
    line: int | None = Field(...)

    confidence: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
    ] = Field(...)

    evidence: list[str] = Field(...)
    next_step: str = Field(...)

    proposed_change: str = Field(...)
    affected_files: list[str] = Field(...)

    change_size: Literal[
        "NONE",
        "SMALL",
        "MEDIUM",
        "LARGE",
    ] = Field(...)

    exact_change: ExactChange = Field(...)


def to_json_object(
    value: object,
) -> JsonObject | None:
    if not isinstance(
        value,
        dict,
    ):
        return None

    object_value = cast(
        dict[object, object],
        value,
    )

    for key in object_value:
        if not isinstance(
            key,
            str,
        ):
            return None

    return cast(
        JsonObject,
        value,
    )


def load_jsonl(
    path: Path,
) -> list[JsonObject]:
    if not path.exists():
        return []

    records: list[
        JsonObject
    ] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                value: object = (
                    json.loads(line)
                )
            except json.JSONDecodeError:
                continue

            record = to_json_object(
                value
            )

            if record is not None:
                records.append(record)

    return records


def normalize_path(
    path: str,
) -> str:
    return path.replace(
        "\\",
        "/",
    ).lstrip("./")


def load_evidence() -> list[JsonObject]:
    return load_jsonl(
        EVIDENCE_FILE
    )


def load_project_context() -> list[JsonObject]:
    return load_jsonl(
        CONTEXT_FILE
    )


def get_object(
    record: JsonObject,
    key: str,
) -> JsonObject | None:
    value = record.get(key)

    if not isinstance(
        value,
        dict,
    ):
        return None

    return to_json_object(
        value
    )


def get_string(
    record: JsonObject,
    key: str,
) -> str:
    value = record.get(key)

    if isinstance(
        value,
        str,
    ):
        return value

    return ""


def get_int(
    record: JsonObject,
    key: str,
) -> int | None:
    value = record.get(key)

    if isinstance(
        value,
        int,
    ):
        return value

    return None


def get_test_status(
    evidence: JsonObject,
) -> str:
    test = get_object(
        evidence,
        "test",
    )

    if test is None:
        return "UNKNOWN"

    status = get_string(
        test,
        "status",
    )

    if status:
        return status

    return "UNKNOWN"


def get_affected_file(
    evidence: JsonObject,
) -> str | None:
    test = get_object(
        evidence,
        "test",
    )

    if test is not None:
        failures = test.get(
            "failures"
        )

        if isinstance(
            failures,
            list,
        ):
            for failure in failures:
                if not isinstance(
                    failure,
                    dict,
                ):
                    continue

                failure_object = (
                    to_json_object(
                        failure
                    )
                )

                if failure_object is None:
                    continue

                file = get_string(
                    failure_object,
                    "file",
                )

                if file:
                    return file

    errors = evidence.get(
        "errors"
    )

    if isinstance(
        errors,
        list,
    ):
        for error in errors:
            if not isinstance(
                error,
                dict,
            ):
                continue

            error_object = (
                to_json_object(
                    error
                )
            )

            if error_object is None:
                continue

            file = get_string(
                error_object,
                "file",
            )

            if file:
                return file

    static_analysis = evidence.get(
        "static_analysis"
    )

    if isinstance(
        static_analysis,
        list,
    ):
        for finding in static_analysis:
            if not isinstance(
                finding,
                dict,
            ):
                continue

            finding_object = (
                to_json_object(
                    finding
                )
            )

            if finding_object is None:
                continue

            file = get_string(
                finding_object,
                "file",
            )

            if file:
                return file

    change_session = get_object(
        evidence,
        "change_session",
    )

    if change_session is not None:
        files = change_session.get(
            "files"
        )

        if isinstance(
            files,
            list,
        ):
            for file in files:
                if isinstance(
                    file,
                    str,
                ):
                    return file

    return None


def get_context_for_file(
    context_records: list[JsonObject],
    file_path: str,
) -> JsonObject | None:
    normalized_target = normalize_path(
        file_path
    )

    for record in context_records:
        path = get_string(
            record,
            "path",
        )

        if not path:
            continue

        if (
            normalize_path(path)
            == normalized_target
        ):
            return record

    return None


def get_relevant_context(
    evidence: JsonObject,
    context_records: list[JsonObject],
) -> list[JsonObject]:
    relevant_context: list[
        JsonObject
    ] = []

    affected_file = get_affected_file(
        evidence
    )

    if affected_file:
        context = (
            get_context_for_file(
                context_records,
                affected_file,
            )
        )

        if context is not None:
            relevant_context.append(
                context
            )

    change_session = get_object(
        evidence,
        "change_session",
    )

    if change_session is not None:
        files = change_session.get(
            "files"
        )

        if isinstance(
            files,
            list,
        ):
            for file in files:
                if not isinstance(
                    file,
                    str,
                ):
                    continue

                context = (
                    get_context_for_file(
                        context_records,
                        file,
                    )
                )

                if context is None:
                    continue

                already_added = any(
                    get_string(
                        existing,
                        "path",
                    )
                    == get_string(
                        context,
                        "path",
                    )
                    for existing
                    in relevant_context
                )

                if not already_added:
                    relevant_context.append(
                        context
                    )

    return relevant_context


def build_prompt(
    evidence: JsonObject,
    context_records: list[JsonObject],
) -> str:
    evidence_json = json.dumps(
        evidence,
        indent=2,
        ensure_ascii=False,
    )

    context_json = json.dumps(
        context_records,
        indent=2,
        ensure_ascii=False,
    )

    return f"""
You are an AI Developer Overseer.

Analyze the supplied project evidence and source code.

Your job is to diagnose software problems and propose a change when
the supplied evidence supports one.

Rules:
- Use only the supplied evidence and source context.
- Do not invent files, errors, test results, or source code.
- Identify the most likely cause.
- Identify the affected file when possible.
- Identify the affected line when possible.
- Give a confidence level.
- Give a practical next step.
- If a change is needed, describe the proposed change clearly.
- Do not write replacement code unless it is placed inside the
  exact_change fields.
- Do not produce a full rewritten file.
- Do not propose unrelated improvements.
- Do not change architecture unless the evidence requires it.
- If there is no supported change, use change_size "NONE".
- affected_files must contain only files supported by the evidence
  or supplied source context.

Important source-context rule:
- The supplied source context is the authoritative current source.
- Do not assume source code that is not included in the context.
- If the source context contains the affected test or function,
  inspect it before proposing a change.
- Do not diagnose a specific implementation as incorrect unless
  the supplied source supports that conclusion.

Exact change rules:
- exact_change describes one specific file edit that can be safely
  applied mechanically.
- file must identify the exact file being changed.
- line must identify the relevant line when known.
- old_text must contain the exact existing text that should be
  replaced.
- new_text must contain the exact replacement text.
- Only provide new_text when the supplied evidence and source
  context establish exactly what the replacement should be.
- Never guess a replacement value.
- If the correct replacement cannot be established from the
  supplied evidence, set new_text to null.
- If an exact mechanical edit cannot be established, set the
  exact_change fields to null where appropriate.
- The change applier will refuse to modify files when new_text
  is missing.
- An approved permission does not give permission to guess.

change_size means:
NONE = no change should be made.
SMALL = a localized change affecting a small part of the project.
MEDIUM = a change affecting multiple related parts.
LARGE = a substantial change affecting project architecture or
multiple major components.

The proposed change will be shown to the developer for permission.
Do not assume permission has been granted.

Return only structured data matching the requested schema.

Project evidence:
{evidence_json}

Relevant source context:
{context_json}
""".strip()


def diagnose_evidence(
    client: ModelsAPI,
    evidence: JsonObject,
    context_records: list[JsonObject],
) -> Diagnosis:
    prompt = build_prompt(
        evidence,
        context_records,
    )

    response = client.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=Diagnosis,
            automatic_function_calling=(
                types.AutomaticFunctionCallingConfig(
                    disable=True,
                )
            ),
        ),
    )

    if not response.text:
        raise RuntimeError(
            "AI returned an empty response."
        )

    return Diagnosis.model_validate_json(
        response.text
    )


def write_diagnosis(
    evidence: JsonObject,
    diagnosis: Diagnosis,
    transaction_id: str | None = None,
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    diagnosis_data = (
        diagnosis.model_dump()
    )

    record: JsonObject = {
        "run_id": get_string(
            evidence,
            "run_id",
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(
            timespec="milliseconds"
        ),
        "test_timestamp": get_string(
            evidence,
            "timestamp",
        ),
        "test_status": get_test_status(
            evidence,
        ),
        "diagnosis": cast(
            JsonValue,
            diagnosis_data,
        ),
    }
    if transaction_id is not None:
        transaction = get_transaction(
            transaction_id,
            CHANGE_TRANSACTIONS_FILE,
        )
        diagnosis_run_id = get_string(evidence, "run_id")
        if (
            transaction is None
            or transaction["state"] != "PROPOSED"
            or transaction["diagnosis_run_id"] != diagnosis_run_id
            or transaction["pre_change_run_id"] != diagnosis_run_id
        ):
            raise TransactionLogError(
                "Transaction ID does not match the diagnosed test run."
            )
        record["transaction_id"] = transaction_id

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
    diagnosis: Diagnosis,
) -> None:
    print()
    print("=" * 50)
    print("AI DIAGNOSIS")
    print("=" * 50)

    print(
        f"Status: {diagnosis.status}"
    )

    print(
        f"Diagnosis: "
        f"{diagnosis.diagnosis}"
    )

    print(
        f"Likely cause: "
        f"{diagnosis.likely_cause}"
    )

    print(
        f"File: "
        f"{diagnosis.file or 'Unknown'}"
    )

    print(
        f"Line: "
        f"{diagnosis.line or 'Unknown'}"
    )

    print(
        f"Confidence: "
        f"{diagnosis.confidence}"
    )

    print()
    print("Evidence:")

    for evidence_number, evidence_item in enumerate(
        diagnosis.evidence,
        start=1,
    ):
        print(
            f"{evidence_number}. "
            f"{evidence_item}"
        )

    print()

    print(
        f"Next step: "
        f"{diagnosis.next_step}"
    )

    print()

    print(
        "Proposed change:"
    )

    print(
        diagnosis.proposed_change
    )

    print()

    print(
        "Affected files:"
    )

    if diagnosis.affected_files:
        for file_path in (
            diagnosis.affected_files
        ):
            print(
                f"  {file_path}"
            )
    else:
        print(
            "  None"
        )

    print()

    print(
        "Exact change:"
    )

    print(
        f"File: "
        f"{diagnosis.exact_change.file or 'None'}"
    )

    print(
        f"Line: "
        f"{diagnosis.exact_change.line or 'None'}"
    )

    print(
        f"Old text: "
        f"{diagnosis.exact_change.old_text or 'None'}"
    )

    print(
        f"New text: "
        f"{diagnosis.exact_change.new_text or 'None'}"
    )

    print()

    print(
        f"Change size: "
        f"{diagnosis.change_size}"
    )

    print("=" * 50)


def main(transaction_id: str | None = None) -> None:
    evidence_records = load_evidence()

    if not evidence_records:
        print(
            "No evidence found."
        )
        return

    context_records = (
        load_project_context()
    )

    api_key = os.getenv(
        "GEMINI_API_KEY"
    )

    if not api_key:
        print(
            "GEMINI_API_KEY is not set."
        )
        return

    client = genai.Client(
        api_key=api_key,
    )

    for evidence in evidence_records[-1:]:
        try:
            relevant_context = (
                get_relevant_context(
                    evidence,
                    context_records,
                )
            )

            diagnosis = diagnose_evidence(
                client.models,
                evidence,
                relevant_context,
            )

            write_diagnosis(
                evidence,
                diagnosis,
                transaction_id,
            )

            print_diagnosis(
                diagnosis
            )

        except Exception as error:
            print(
                f"Failed to diagnose evidence: "
                f"{error}"
            )
            if transaction_id is not None:
                raise SystemExit(1) from error


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction-id")
    main(parser.parse_args().transaction_id)