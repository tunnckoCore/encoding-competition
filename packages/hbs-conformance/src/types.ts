import type {
  DecodeResult,
  GuardIssue,
  GuardOptions,
  HbsOptions,
  Hole,
  IntegrityOptions,
} from "@tunnckocore/hbs";

export type {
  DecodeResult,
  GuardIssue,
  GuardOptions,
  HbsOptions,
  Hole,
  IntegrityOptions,
};

export type EnvelopeParts = {
  integrityHash: string;
  bodyLen: number;
  schemaLen: number;
  keysLen: number;
  guardsLen: number;
  body: string;
  T: string;
  K: string;
  G: string;
  V: string;
  payload: string;
};

type PositiveVectorBase = {
  id: string;
  description: string;
  features: string[];
  options: HbsOptions;
  hbs: string;
  envelope: EnvelopeParts;
};

export type RoundtripVector = PositiveVectorBase & {
  kind: "roundtrip";
  input: unknown;
  expectedDecode: DecodeResult;
};

export type EncodeVector = PositiveVectorBase & {
  kind: "encode";
  input: unknown;
};

export type DecodeVector = PositiveVectorBase & {
  kind: "decode";
  expectedDecode: DecodeResult;
};

export type PositiveVector = RoundtripVector | EncodeVector | DecodeVector;

type RejectVectorBase = {
  id: string;
  description: string;
  options: HbsOptions;
  expectedError: string;
};

export type RejectEncodeVector = RejectVectorBase & {
  kind: "reject-encode";
  input: unknown;
};

export type RejectDecodeVector = RejectVectorBase & {
  kind: "reject-decode";
  hbs: string;
};

export type RejectVector = RejectEncodeVector | RejectDecodeVector;

export type ConformanceVector = PositiveVector | RejectVector;

export type ConformanceVectorSet = {
  format: "hbs3-conformance-v1";
  spec: string;
  generatedBy: string;
  notes: string[];
  commandContract: Record<string, unknown>;
  vectors: PositiveVector[];
  rejects: RejectVector[];
};
