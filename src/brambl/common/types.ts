import * as lock from '../../../proto/brambl/models/box/lock.js';
import * as value from '../../../proto/brambl/models/box/value.js';
import * as challenge from "../../../proto/brambl/models/box/challenge.js";
import * as asset from "../../../proto/brambl/models/box/asset.js";
import * as datum from '../../../proto/brambl/models/datum.js'
import * as event from '../../../proto/brambl/models/event.js';
import * as address from '../../../proto/brambl/models/address.js';
import * as identifier from '../../../proto/brambl/models/identifier.js';
import * as evidence from '../../../proto/brambl/models/evidence.js';
import * as common from '../../../proto/brambl/models/common.js';
import * as attestation from '../../../proto/brambl/models/transaction/attestation.js';
import * as schedule from '../../../proto/brambl/models/transaction/schedule.js';
import * as spent_transaction_output from '../../../proto/brambl/models/transaction/spent_transaction_output.js';
import * as unspent_transaction_output from '../../../proto/brambl/models/transaction/unspent_transaction_output.js';
import * as io_transaction from '../../../proto/brambl/models/transaction/io_transaction.js';
import * as txo from '../../../proto/genus/genus_models.js';

//Asset
export const FungibilityType = asset.co.topl.brambl.models.box.FungibilityType;

//Lock
export class Lock extends lock.co.topl.brambl.models.box.Lock { };
export class Lock_Predicate extends lock.co.topl.brambl.models.box.Lock.Predicate { };
export class Lock_Image extends lock.co.topl.brambl.models.box.Lock.Image { };
export class Lock_Commitment extends lock.co.topl.brambl.models.box.Lock.Commitment { };

//Value
export class Value extends value.co.topl.brambl.models.box.Value { };

//Identifier
export class LockId extends identifier.co.topl.brambl.models.LockId { };
export class AccumulatorRootId extends identifier.co.topl.brambl.models.AccumulatorRootId { };
export class GroupId extends identifier.co.topl.brambl.models.GroupId { };
export class SeriesId extends identifier.co.topl.brambl.models.SeriesId { };
export class TransactionId extends identifier.co.topl.brambl.models.TransactionId { };

//Datum
export class Datum extends datum.co.topl.brambl.models.Datum { };
export class Datum_IoTransaction extends datum.co.topl.brambl.models.Datum.IoTransaction { };
export class Datum_GroupPolicy extends datum.co.topl.brambl.models.Datum.GroupPolicy { };
export class Datum_SeriesPolicy extends datum.co.topl.brambl.models.Datum.SeriesPolicy { };

//Event
export class Event extends event.co.topl.brambl.models.Event { };
export class Event_IoTransaction extends event.co.topl.brambl.models.Event.IoTransaction { };
export class Event_GroupPolicy extends event.co.topl.brambl.models.Event.GroupPolicy { };
export class Event_SeriesPolicy extends event.co.topl.brambl.models.Event.SeriesPolicy { };

//Schedule
export class Schedule extends schedule.co.topl.brambl.models.transaction.Schedule { };

//Address
export class LockAddress extends address.co.topl.brambl.models.LockAddress { };
export class TransactionOutputAddress extends address.co.topl.brambl.models.TransactionOutputAddress { };

//Attestation
export class Attestation extends attestation.co.topl.brambl.models.transaction.Attestation { };

//Spent Transaction Output
export class SpentTransactionOutput extends spent_transaction_output.co.topl.brambl.models.transaction.SpentTransactionOutput { };

//Unspent Transaction Output
export class UnspentTransactionOutput extends unspent_transaction_output.co.topl.brambl.models.transaction.UnspentTransactionOutput { };

//IO Transaction
export class IoTransaction extends io_transaction.co.topl.brambl.models.transaction.IoTransaction { };

//TXO
export class Txo extends txo.co.topl.genus.services.Txo { };

//Challenge
export class Challenge extends challenge.co.topl.brambl.models.box.Challenge { };

//Evidence
export class Evidence extends evidence.co.topl.brambl.models.Evidence { };

//Common
export class ImmutableBytes extends common.co.topl.brambl.models.common.ImmutableBytes { };