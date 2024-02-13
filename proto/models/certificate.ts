/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: models/certificate.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as dependency_1 from "./verification_key";
import * as dependency_2 from "./proof";
import * as pb_1 from "google-protobuf";
export namespace co.topl.proto.models {
    export class OperationalCertificate extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            parentVK?: dependency_1.co.topl.proto.models.VerificationKeyKesProduct;
            parentSignature?: dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct;
            childVK?: dependency_1.co.topl.proto.models.VerificationKeyEd25519;
            childSignature?: dependency_2.co.topl.proto.models.ProofKnowledgeEd25519;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("parentVK" in data && data.parentVK != undefined) {
                    this.parentVK = data.parentVK;
                }
                if ("parentSignature" in data && data.parentSignature != undefined) {
                    this.parentSignature = data.parentSignature;
                }
                if ("childVK" in data && data.childVK != undefined) {
                    this.childVK = data.childVK;
                }
                if ("childSignature" in data && data.childSignature != undefined) {
                    this.childSignature = data.childSignature;
                }
            }
        }
        get parentVK() {
            return pb_1.Message.getWrapperField(this, dependency_1.co.topl.proto.models.VerificationKeyKesProduct, 1) as dependency_1.co.topl.proto.models.VerificationKeyKesProduct;
        }
        set parentVK(value: dependency_1.co.topl.proto.models.VerificationKeyKesProduct) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_parentVK() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get parentSignature() {
            return pb_1.Message.getWrapperField(this, dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct, 2) as dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct;
        }
        set parentSignature(value: dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct) {
            pb_1.Message.setWrapperField(this, 2, value);
        }
        get has_parentSignature() {
            return pb_1.Message.getField(this, 2) != null;
        }
        get childVK() {
            return pb_1.Message.getWrapperField(this, dependency_1.co.topl.proto.models.VerificationKeyEd25519, 3) as dependency_1.co.topl.proto.models.VerificationKeyEd25519;
        }
        set childVK(value: dependency_1.co.topl.proto.models.VerificationKeyEd25519) {
            pb_1.Message.setWrapperField(this, 3, value);
        }
        get has_childVK() {
            return pb_1.Message.getField(this, 3) != null;
        }
        get childSignature() {
            return pb_1.Message.getWrapperField(this, dependency_2.co.topl.proto.models.ProofKnowledgeEd25519, 4) as dependency_2.co.topl.proto.models.ProofKnowledgeEd25519;
        }
        set childSignature(value: dependency_2.co.topl.proto.models.ProofKnowledgeEd25519) {
            pb_1.Message.setWrapperField(this, 4, value);
        }
        get has_childSignature() {
            return pb_1.Message.getField(this, 4) != null;
        }
        static fromObject(data: {
            parentVK?: ReturnType<typeof dependency_1.co.topl.proto.models.VerificationKeyKesProduct.prototype.toObject>;
            parentSignature?: ReturnType<typeof dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct.prototype.toObject>;
            childVK?: ReturnType<typeof dependency_1.co.topl.proto.models.VerificationKeyEd25519.prototype.toObject>;
            childSignature?: ReturnType<typeof dependency_2.co.topl.proto.models.ProofKnowledgeEd25519.prototype.toObject>;
        }): OperationalCertificate {
            const message = new OperationalCertificate({});
            if (data.parentVK != null) {
                message.parentVK = dependency_1.co.topl.proto.models.VerificationKeyKesProduct.fromObject(data.parentVK);
            }
            if (data.parentSignature != null) {
                message.parentSignature = dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct.fromObject(data.parentSignature);
            }
            if (data.childVK != null) {
                message.childVK = dependency_1.co.topl.proto.models.VerificationKeyEd25519.fromObject(data.childVK);
            }
            if (data.childSignature != null) {
                message.childSignature = dependency_2.co.topl.proto.models.ProofKnowledgeEd25519.fromObject(data.childSignature);
            }
            return message;
        }
        toObject() {
            const data: {
                parentVK?: ReturnType<typeof dependency_1.co.topl.proto.models.VerificationKeyKesProduct.prototype.toObject>;
                parentSignature?: ReturnType<typeof dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct.prototype.toObject>;
                childVK?: ReturnType<typeof dependency_1.co.topl.proto.models.VerificationKeyEd25519.prototype.toObject>;
                childSignature?: ReturnType<typeof dependency_2.co.topl.proto.models.ProofKnowledgeEd25519.prototype.toObject>;
            } = {};
            if (this.parentVK != null) {
                data.parentVK = this.parentVK.toObject();
            }
            if (this.parentSignature != null) {
                data.parentSignature = this.parentSignature.toObject();
            }
            if (this.childVK != null) {
                data.childVK = this.childVK.toObject();
            }
            if (this.childSignature != null) {
                data.childSignature = this.childSignature.toObject();
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_parentVK)
                writer.writeMessage(1, this.parentVK, () => this.parentVK.serialize(writer));
            if (this.has_parentSignature)
                writer.writeMessage(2, this.parentSignature, () => this.parentSignature.serialize(writer));
            if (this.has_childVK)
                writer.writeMessage(3, this.childVK, () => this.childVK.serialize(writer));
            if (this.has_childSignature)
                writer.writeMessage(4, this.childSignature, () => this.childSignature.serialize(writer));
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): OperationalCertificate {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new OperationalCertificate();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.parentVK, () => message.parentVK = dependency_1.co.topl.proto.models.VerificationKeyKesProduct.deserialize(reader));
                        break;
                    case 2:
                        reader.readMessage(message.parentSignature, () => message.parentSignature = dependency_2.co.topl.proto.models.ProofKnowledgeKesProduct.deserialize(reader));
                        break;
                    case 3:
                        reader.readMessage(message.childVK, () => message.childVK = dependency_1.co.topl.proto.models.VerificationKeyEd25519.deserialize(reader));
                        break;
                    case 4:
                        reader.readMessage(message.childSignature, () => message.childSignature = dependency_2.co.topl.proto.models.ProofKnowledgeEd25519.deserialize(reader));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): OperationalCertificate {
            return OperationalCertificate.deserialize(bytes);
        }
    }
    export class EligibilityCertificate extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            vrfSig?: dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519;
            vrfVK?: dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519;
            thresholdEvidence?: Uint8Array;
            eta?: Uint8Array;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("vrfSig" in data && data.vrfSig != undefined) {
                    this.vrfSig = data.vrfSig;
                }
                if ("vrfVK" in data && data.vrfVK != undefined) {
                    this.vrfVK = data.vrfVK;
                }
                if ("thresholdEvidence" in data && data.thresholdEvidence != undefined) {
                    this.thresholdEvidence = data.thresholdEvidence;
                }
                if ("eta" in data && data.eta != undefined) {
                    this.eta = data.eta;
                }
            }
        }
        get vrfSig() {
            return pb_1.Message.getWrapperField(this, dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519, 1) as dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519;
        }
        set vrfSig(value: dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_vrfSig() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get vrfVK() {
            return pb_1.Message.getWrapperField(this, dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519, 2) as dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519;
        }
        set vrfVK(value: dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519) {
            pb_1.Message.setWrapperField(this, 2, value);
        }
        get has_vrfVK() {
            return pb_1.Message.getField(this, 2) != null;
        }
        get thresholdEvidence() {
            return pb_1.Message.getFieldWithDefault(this, 3, new Uint8Array(0)) as Uint8Array;
        }
        set thresholdEvidence(value: Uint8Array) {
            pb_1.Message.setField(this, 3, value);
        }
        get eta() {
            return pb_1.Message.getFieldWithDefault(this, 4, new Uint8Array(0)) as Uint8Array;
        }
        set eta(value: Uint8Array) {
            pb_1.Message.setField(this, 4, value);
        }
        static fromObject(data: {
            vrfSig?: ReturnType<typeof dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519.prototype.toObject>;
            vrfVK?: ReturnType<typeof dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519.prototype.toObject>;
            thresholdEvidence?: Uint8Array;
            eta?: Uint8Array;
        }): EligibilityCertificate {
            const message = new EligibilityCertificate({});
            if (data.vrfSig != null) {
                message.vrfSig = dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519.fromObject(data.vrfSig);
            }
            if (data.vrfVK != null) {
                message.vrfVK = dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519.fromObject(data.vrfVK);
            }
            if (data.thresholdEvidence != null) {
                message.thresholdEvidence = data.thresholdEvidence;
            }
            if (data.eta != null) {
                message.eta = data.eta;
            }
            return message;
        }
        toObject() {
            const data: {
                vrfSig?: ReturnType<typeof dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519.prototype.toObject>;
                vrfVK?: ReturnType<typeof dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519.prototype.toObject>;
                thresholdEvidence?: Uint8Array;
                eta?: Uint8Array;
            } = {};
            if (this.vrfSig != null) {
                data.vrfSig = this.vrfSig.toObject();
            }
            if (this.vrfVK != null) {
                data.vrfVK = this.vrfVK.toObject();
            }
            if (this.thresholdEvidence != null) {
                data.thresholdEvidence = this.thresholdEvidence;
            }
            if (this.eta != null) {
                data.eta = this.eta;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_vrfSig)
                writer.writeMessage(1, this.vrfSig, () => this.vrfSig.serialize(writer));
            if (this.has_vrfVK)
                writer.writeMessage(2, this.vrfVK, () => this.vrfVK.serialize(writer));
            if (this.thresholdEvidence.length)
                writer.writeBytes(3, this.thresholdEvidence);
            if (this.eta.length)
                writer.writeBytes(4, this.eta);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): EligibilityCertificate {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new EligibilityCertificate();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.vrfSig, () => message.vrfSig = dependency_2.co.topl.proto.models.ProofKnowledgeVrfEd25519.deserialize(reader));
                        break;
                    case 2:
                        reader.readMessage(message.vrfVK, () => message.vrfVK = dependency_1.co.topl.proto.models.VerificationKeyVrfEd25519.deserialize(reader));
                        break;
                    case 3:
                        message.thresholdEvidence = reader.readBytes();
                        break;
                    case 4:
                        message.eta = reader.readBytes();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): EligibilityCertificate {
            return EligibilityCertificate.deserialize(bytes);
        }
    }
}