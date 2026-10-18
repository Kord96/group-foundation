import { BOOTSTRAP_PRESENTATION_DOMAIN, type BootstrapPresentation, type UnsignedBootstrapPresentation } from "./contracts.js";
import { bootstrapPresentationJson, encodeBootstrapJson, validateUnsignedBootstrapPresentation } from "./wire.js";

/** Domain-separated signature transcript containing every presentation field except the proof itself. */
export function bootstrapPresentationTranscript(value: BootstrapPresentation | UnsignedBootstrapPresentation): Uint8Array {
  const unsigned = value as UnsignedBootstrapPresentation;
  validateUnsignedBootstrapPresentation(unsigned);
  return encodeBootstrapJson({ domain: BOOTSTRAP_PRESENTATION_DOMAIN, presentation: bootstrapPresentationJson(unsigned, false) });
}
