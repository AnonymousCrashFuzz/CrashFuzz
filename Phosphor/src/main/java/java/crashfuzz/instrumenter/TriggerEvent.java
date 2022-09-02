package java.crashfuzz.instrumenter;

public enum TriggerEvent {
	CRASH,  //crash current node
	CONTI, //keep execution
	REBOOT,
}
