/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: node/models/node_config.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as pb_1 from "google-protobuf";
export namespace co.topl.proto.node {
    export class NodeConfigMap extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            slotConfigMap?: Map<number, NodeConfig>;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("slotConfigMap" in data && data.slotConfigMap != undefined) {
                    this.slotConfigMap = data.slotConfigMap;
                }
            }
            if (!this.slotConfigMap)
                this.slotConfigMap = new Map();
        }
        get slotConfigMap() {
            return pb_1.Message.getField(this, 1) as any as Map<number, NodeConfig>;
        }
        set slotConfigMap(value: Map<number, NodeConfig>) {
            pb_1.Message.setField(this, 1, value as any);
        }
        static fromObject(data: {
            slotConfigMap?: {
                [key: number]: ReturnType<typeof NodeConfig.prototype.toObject>;
            };
        }): NodeConfigMap {
            const message = new NodeConfigMap({});
            if (typeof data.slotConfigMap == "object") {
                message.slotConfigMap = new Map(Object.entries(data.slotConfigMap).map(([key, value]) => [Number(key), NodeConfig.fromObject(value)]));
            }
            return message;
        }
        toObject() {
            const data: {
                slotConfigMap?: {
                    [key: number]: ReturnType<typeof NodeConfig.prototype.toObject>;
                };
            } = {};
            if (this.slotConfigMap != null) {
                data.slotConfigMap = (Object.fromEntries)((Array.from)(this.slotConfigMap).map(([key, value]) => [key, value.toObject()]));
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            for (const [key, value] of this.slotConfigMap) {
                writer.writeMessage(1, this.slotConfigMap, () => {
                    writer.writeUint64(1, key);
                    writer.writeMessage(2, value, () => value.serialize(writer));
                });
            }
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): NodeConfigMap {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new NodeConfigMap();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message, () => pb_1.Map.deserializeBinary(message.slotConfigMap as any, reader, reader.readUint64, () => {
                            let value;
                            reader.readMessage(message, () => value = NodeConfig.deserialize(reader));
                            return value;
                        }));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): NodeConfigMap {
            return NodeConfigMap.deserialize(bytes);
        }
    }
    export class NodeConfig extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            slotDurationMillis?: number;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("slotDurationMillis" in data && data.slotDurationMillis != undefined) {
                    this.slotDurationMillis = data.slotDurationMillis;
                }
            }
        }
        get slotDurationMillis() {
            return pb_1.Message.getFieldWithDefault(this, 1, 0) as number;
        }
        set slotDurationMillis(value: number) {
            pb_1.Message.setField(this, 1, value);
        }
        static fromObject(data: {
            slotDurationMillis?: number;
        }): NodeConfig {
            const message = new NodeConfig({});
            if (data.slotDurationMillis != null) {
                message.slotDurationMillis = data.slotDurationMillis;
            }
            return message;
        }
        toObject() {
            const data: {
                slotDurationMillis?: number;
            } = {};
            if (this.slotDurationMillis != null) {
                data.slotDurationMillis = this.slotDurationMillis;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.slotDurationMillis != 0)
                writer.writeUint32(1, this.slotDurationMillis);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): NodeConfig {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new NodeConfig();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.slotDurationMillis = reader.readUint32();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): NodeConfig {
            return NodeConfig.deserialize(bytes);
        }
    }
}