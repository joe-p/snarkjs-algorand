import algosdk from "algosdk";
import {
  ARC56AppClient,
  type AppClientMethodParams,
  type BareCreateParams,
  type BareExecutionResult,
  type CreateMethodParams,
  type MethodParams,
  type MethodExecutionResult,
  type ARC56Contract,
} from "@joe-p/algokit-lite";

type TypedMethodParams<TArgs = undefined> = Omit<
  AppClientMethodParams,
  "method" | "methodArgs"
> &
  (TArgs extends undefined ? { args?: undefined } : { args: TArgs });
type TypedCreateMethodParams<TArgs = undefined> = Omit<
  CreateMethodParams,
  "method" | "methodArgs"
> &
  (TArgs extends undefined ? { args?: undefined } : { args: TArgs });
type TypedBareCreateParams = Omit<
  BareCreateParams,
  "arc56" | "algod" | "getSuggestedParams" | "templateVariables"
>;

export const ARC56_JSON =
  '{"name":"Groth16Bls12381SignalsAndProof","structs":{"Groth16Bls12381Proof":[{"name":"pi_a","type":"byte[96]"},{"name":"pi_b","type":"byte[192]"},{"name":"pi_c","type":"byte[96]"}]},"methods":[{"name":"signalsAndProof","args":[{"type":"uint256[]","name":"signals"},{"type":"(byte[96],byte[192],byte[96])","struct":"Groth16Bls12381Proof","name":"proof"}],"returns":{"type":"void"},"actions":{"create":[],"call":["NoOp"]},"readonly":false,"events":[],"recommendations":{}}],"arcs":[22,28],"networks":{},"state":{"schema":{"global":{"ints":0,"bytes":0},"local":{"ints":0,"bytes":0}},"keys":{"global":{},"local":{},"box":{}},"maps":{"global":{},"local":{},"box":{}}},"bareActions":{"create":["NoOp"],"call":[]},"sourceInfo":{"approval":{"sourceInfo":[{"pc":[44],"errorMessage":"invalid array length header"},{"pc":[54],"errorMessage":"invalid number of bytes for arc4.dynamic_array<arc4.uint256>"},{"pc":[63],"errorMessage":"invalid number of bytes for contracts/groth16_bls12381.algo.ts::Groth16Bls12381Proof"}],"pcOffsetMethod":"none"},"clear":{"sourceInfo":[],"pcOffsetMethod":"none"}},"source":{"approval":"I3ByYWdtYSB2ZXJzaW9uIDExCiNwcmFnbWEgdHlwZXRyYWNrIGZhbHNlCgovLyBAYWxnb3JhbmRmb3VuZGF0aW9uL2FsZ29yYW5kLXR5cGVzY3JpcHQvYXJjNC9pbmRleC5kLnRzOjpDb250cmFjdC5hcHByb3ZhbFByb2dyYW0oKSAtPiB1aW50NjQ6Cm1haW46CiAgICAvLyBjb250cmFjdHMvZ3JvdGgxNl9ibHMxMjM4MV92ZXJpZmllci5hbGdvLnRzOjYzCiAgICAvLyBleHBvcnQgY2xhc3MgR3JvdGgxNkJsczEyMzgxU2lnbmFsc0FuZFByb29mIGV4dGVuZHMgQ29udHJhY3QgewogICAgdHhuIE51bUFwcEFyZ3MKICAgIGJ6IG1haW5fX19hbGdvdHNfXy5kZWZhdWx0Q3JlYXRlQDUKICAgIHB1c2hieXRlcyAweDlkN2ZlOGVmIC8vIG1ldGhvZCAic2lnbmFsc0FuZFByb29mKHVpbnQyNTZbXSwoYnl0ZVs5Nl0sYnl0ZVsxOTJdLGJ5dGVbOTZdKSl2b2lkIgogICAgdHhuYSBBcHBsaWNhdGlvbkFyZ3MgMAogICAgbWF0Y2ggbWFpbl9zaWduYWxzQW5kUHJvb2Zfcm91dGVAMwogICAgZXJyCgptYWluX3NpZ25hbHNBbmRQcm9vZl9yb3V0ZUAzOgogICAgLy8gY29udHJhY3RzL2dyb3RoMTZfYmxzMTIzODFfdmVyaWZpZXIuYWxnby50czo2NC02NwogICAgLy8gcHVibGljIHNpZ25hbHNBbmRQcm9vZigKICAgIC8vICAgc2lnbmFsczogUHVibGljU2lnbmFscywKICAgIC8vICAgcHJvb2Y6IEdyb3RoMTZCbHMxMjM4MVByb29mLAogICAgLy8gKTogdm9pZCB7fQogICAgdHhuIE9uQ29tcGxldGlvbgogICAgIQogICAgdHhuIEFwcGxpY2F0aW9uSUQKICAgICYmCiAgICBhc3NlcnQKICAgIGIgc2lnbmFsc0FuZFByb29mCgptYWluX19fYWxnb3RzX18uZGVmYXVsdENyZWF0ZUA1OgogICAgLy8gY29udHJhY3RzL2dyb3RoMTZfYmxzMTIzODFfdmVyaWZpZXIuYWxnby50czo2MwogICAgLy8gZXhwb3J0IGNsYXNzIEdyb3RoMTZCbHMxMjM4MVNpZ25hbHNBbmRQcm9vZiBleHRlbmRzIENvbnRyYWN0IHsKICAgIHR4biBPbkNvbXBsZXRpb24KICAgICEKICAgIHR4biBBcHBsaWNhdGlvbklECiAgICAhCiAgICAmJgogICAgcmV0dXJuCgoKLy8gY29udHJhY3RzL2dyb3RoMTZfYmxzMTIzODFfdmVyaWZpZXIuYWxnby50czo6R3JvdGgxNkJsczEyMzgxU2lnbmFsc0FuZFByb29mLnNpZ25hbHNBbmRQcm9vZltyb3V0aW5nXSgpIC0+IHZvaWQ6CnNpZ25hbHNBbmRQcm9vZjoKICAgIC8vIGNvbnRyYWN0cy9ncm90aDE2X2JsczEyMzgxX3ZlcmlmaWVyLmFsZ28udHM6NjQtNjcKICAgIC8vIHB1YmxpYyBzaWduYWxzQW5kUHJvb2YoCiAgICAvLyAgIHNpZ25hbHM6IFB1YmxpY1NpZ25hbHMsCiAgICAvLyAgIHByb29mOiBHcm90aDE2QmxzMTIzODFQcm9vZiwKICAgIC8vICk6IHZvaWQge30KICAgIHR4bmEgQXBwbGljYXRpb25BcmdzIDEKICAgIGR1cAogICAgcHVzaGludCAwCiAgICBleHRyYWN0X3VpbnQxNiAvLyBvbiBlcnJvcjogaW52YWxpZCBhcnJheSBsZW5ndGggaGVhZGVyCiAgICBwdXNoaW50IDMyCiAgICAqCiAgICBwdXNoaW50IDIKICAgICsKICAgIHN3YXAKICAgIGxlbgogICAgPT0KICAgIGFzc2VydCAvLyBpbnZhbGlkIG51bWJlciBvZiBieXRlcyBmb3IgYXJjNC5keW5hbWljX2FycmF5PGFyYzQudWludDI1Nj4KICAgIHR4bmEgQXBwbGljYXRpb25BcmdzIDIKICAgIGxlbgogICAgcHVzaGludCAzODQKICAgID09CiAgICBhc3NlcnQgLy8gaW52YWxpZCBudW1iZXIgb2YgYnl0ZXMgZm9yIGNvbnRyYWN0cy9ncm90aDE2X2JsczEyMzgxLmFsZ28udHM6Okdyb3RoMTZCbHMxMjM4MVByb29mCiAgICBwdXNoaW50IDEKICAgIHJldHVybgo=","clear":"I3ByYWdtYSB2ZXJzaW9uIDExCiNwcmFnbWEgdHlwZXRyYWNrIGZhbHNlCgovLyBAYWxnb3JhbmRmb3VuZGF0aW9uL2FsZ29yYW5kLXR5cGVzY3JpcHQvYmFzZS1jb250cmFjdC5kLnRzOjpCYXNlQ29udHJhY3QuY2xlYXJTdGF0ZVByb2dyYW0oKSAtPiB1aW50NjQ6Cm1haW46CiAgICBwdXNoaW50IDEKICAgIHJldHVybgo="},"byteCode":{"approval":"CzEbQQAYgASdf+jvNhoAjgEAAQAxGRQxGBBEQgAIMRkUMRgUEEM2GgFJgQBZgSALgQIITBUSRDYaAhWBgAMSRIEBQw==","clear":"C4EBQw=="},"compilerInfo":{"compiler":"puya","compilerVersion":{"major":5,"minor":8,"patch":0}},"events":[],"templateVariables":{}}';

/** The ARC56 contract this client was generated from */
export const APP_SPEC = JSON.parse(ARC56_JSON) as ARC56Contract;

// Aliases for non-encoded ABI values
type uint256 = bigint;

// Type definitions for ARC56 structs
export type Groth16Bls12381Proof = {
  pi_a: Uint8Array;
  pi_b: Uint8Array;
  pi_c: Uint8Array;
};

export type Groth16Bls12381SignalsAndProofReturnTypes = {
  signalsAndProof: void;
};

export class Groth16Bls12381SignalsAndProofClient extends ARC56AppClient {
  constructor(p: {
    appId: bigint | number;
    algod: algosdk.Algodv2;
    getSuggestedParams?: () => Promise<algosdk.SuggestedParams>;
    arc56?: ARC56Contract;
  }) {
    super({ arc56: APP_SPEC, ...p });
  }

  params = {
    signalsAndProof: (
      methodParams: TypedMethodParams<{
        signals: uint256[];
        proof: Groth16Bls12381Proof;
      }>,
    ): MethodParams<
      Groth16Bls12381SignalsAndProofReturnTypes["signalsAndProof"]
    > => {
      return this.getParams<
        Groth16Bls12381SignalsAndProofReturnTypes["signalsAndProof"]
      >({
        method: "signalsAndProof",
        ...methodParams,
        methodArgs: [methodParams.args.signals, methodParams.args.proof],
      });
    },
  };

  call = {
    signalsAndProof: async (
      methodParams: TypedMethodParams<{
        signals: uint256[];
        proof: Groth16Bls12381Proof;
      }>,
    ): Promise<{
      result: MethodExecutionResult;
      returnValue: Groth16Bls12381SignalsAndProofReturnTypes["signalsAndProof"];
    }> => {
      return this.methodCall({
        method: "signalsAndProof",
        ...methodParams,
        methodArgs: [methodParams.args.signals, methodParams.args.proof],
      });
    },
  };

  static create = {
    bare: async (
      params: {
        algod: algosdk.Algodv2;
        getSuggestedParams?: () => Promise<algosdk.SuggestedParams>;
      } & TypedBareCreateParams & {
          templateVariables?: Record<
            string,
            string | bigint | number | Uint8Array
          >;
        },
    ): Promise<{
      appClient: Groth16Bls12381SignalsAndProofClient;
      result: BareExecutionResult;
      appId: bigint;
      appAddress: algosdk.Address;
    }> => {
      const { appId, appAddress, result } = await ARC56AppClient.bareCreate({
        arc56: APP_SPEC,
        ...params,
      });
      return {
        appClient: new Groth16Bls12381SignalsAndProofClient({
          appId,
          algod: params.algod,
          getSuggestedParams: params.getSuggestedParams,
        }),
        appId,
        appAddress,
        result,
      };
    },
  };
}

export default Groth16Bls12381SignalsAndProofClient;
