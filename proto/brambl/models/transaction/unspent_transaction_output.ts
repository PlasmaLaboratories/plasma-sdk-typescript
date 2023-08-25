/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: brambl/models/transaction/unspent_transaction_output.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as dependency_1 from "./../../../validate/validate";
import * as dependency_2 from "./../../../scalapb/scalapb";
import * as dependency_3 from "./../../../scalapb/validate";
import * as dependency_4 from "./../datum";
import * as dependency_5 from "./../address";
import * as dependency_6 from "./../box/value";
import * as pb_1 from "google-protobuf";
export namespace co.topl.brambl.models.transaction {
    export class UnspentTransactionOutput extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            address?: dependency_5.co.topl.brambl.models.Address;
            value?: dependency_6.co.topl.brambl.models.box.Value;
            datum?: dependency_4.co.topl.brambl.models.Datum.UnspentOutput;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("address" in data && data.address != undefined) {
                    this.address = data.address;
                }
                if ("value" in data && data.value != undefined) {
                    this.value = data.value;
                }
                if ("datum" in data && data.datum != undefined) {
                    this.datum = data.datum;
                }
            }
        }
        get address() {
            return pb_1.Message.getWrapperField(this, dependency_5.co.topl.brambl.models.Address, 1) as dependency_5.co.topl.brambl.models.Address;
        }
        set address(value: dependency_5.co.topl.brambl.models.Address) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_address() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get value() {
            return pb_1.Message.getWrapperField(this, dependency_6.co.topl.brambl.models.box.Value, 2) as dependency_6.co.topl.brambl.models.box.Value;
        }
        set value(value: dependency_6.co.topl.brambl.models.box.Value) {
            pb_1.Message.setWrapperField(this, 2, value);
        }
        get has_value() {
            return pb_1.Message.getField(this, 2) != null;
        }
        get datum() {
            return pb_1.Message.getWrapperField(this, dependency_4.co.topl.brambl.models.Datum.UnspentOutput, 3) as dependency_4.co.topl.brambl.models.Datum.UnspentOutput;
        }
        set datum(value: dependency_4.co.topl.brambl.models.Datum.UnspentOutput) {
            pb_1.Message.setWrapperField(this, 3, value);
        }
        get has_datum() {
            return pb_1.Message.getField(this, 3) != null;
        }
        static fromObject(data: {
            address?: ReturnType<typeof dependency_5.co.topl.brambl.models.Address.prototype.toObject>;
            value?: ReturnType<typeof dependency_6.co.topl.brambl.models.box.Value.prototype.toObject>;
            datum?: ReturnType<typeof dependency_4.co.topl.brambl.models.Datum.UnspentOutput.prototype.toObject>;
        }): UnspentTransactionOutput {
            const message = new UnspentTransactionOutput({});
            if (data.address != null) {
                message.address = dependency_5.co.topl.brambl.models.Address.fromObject(data.address);
            }
            if (data.value != null) {
                message.value = dependency_6.co.topl.brambl.models.box.Value.fromObject(data.value);
            }
            if (data.datum != null) {
                message.datum = dependency_4.co.topl.brambl.models.Datum.UnspentOutput.fromObject(data.datum);
            }
            return message;
        }
        toObject() {
            const data: {
                address?: ReturnType<typeof dependency_5.co.topl.brambl.models.Address.prototype.toObject>;
                value?: ReturnType<typeof dependency_6.co.topl.brambl.models.box.Value.prototype.toObject>;
                datum?: ReturnType<typeof dependency_4.co.topl.brambl.models.Datum.UnspentOutput.prototype.toObject>;
            } = {};
            if (this.address != null) {
                data.address = this.address.toObject();
            }
            if (this.value != null) {
                data.value = this.value.toObject();
            }
            if (this.datum != null) {
                data.datum = this.datum.toObject();
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_address)
                writer.writeMessage(1, this.address, () => this.address.serialize(writer));
            if (this.has_value)
                writer.writeMessage(2, this.value, () => this.value.serialize(writer));
            if (this.has_datum)
                writer.writeMessage(3, this.datum, () => this.datum.serialize(writer));
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): UnspentTransactionOutput {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new UnspentTransactionOutput();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.address, () => message.address = dependency_5.co.topl.brambl.models.Address.deserialize(reader));
                        break;
                    case 2:
                        reader.readMessage(message.value, () => message.value = dependency_6.co.topl.brambl.models.box.Value.deserialize(reader));
                        break;
                    case 3:
                        reader.readMessage(message.datum, () => message.datum = dependency_4.co.topl.brambl.models.Datum.UnspentOutput.deserialize(reader));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): UnspentTransactionOutput {
            return UnspentTransactionOutput.deserialize(bytes);
        }
    }
}
