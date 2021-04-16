#include <string>
#include <iostream>
#include <jni.h>
using namespace std;
//#include <jni.h>
//#pragma comment (lib,"C:\\Program Files\\Java\\jdk1.6.0_03\\lib\\jvm.lib")
//#import "C:/Program Files/Java/jdk1.6.0_03/jre/bin/client/jvm.dll"

//#define PATH_SEPARATOR ';' /* define it to be ':' on Solaris */
#define USER_CLASSPATH ".;C:\\Documents and Settings\\Administrator\\My Documents\\NetBeansProjects\\test\\dist\\test.jar" /* where Prog.class is */
//
// Win32 version //
//void *JNU_FindCreateJavaVM(char *vmlibpath)
//{
//	HINSTANCE hVM = LoadLibraryA(vmlibpath);
//	if (hVM == NULL) {
//		return NULL;
//	}
//	return GetProcAddress(hVM, "JNI_CreateJavaVM");
//}


JNIEnv* create_vm() {
	//.;C:\WINNT\System32;C:\WINNT;

	JavaVM* jvm;//=(JavaVM*)JNU_FindCreateJavaVM("C:\\Program Files\\Java\\jdk1.6.0_03\\jre\\bin\\client\\jvm.dll");
	JNIEnv* env;
	JavaVMInitArgs vm_args;
	JNI_GetDefaultJavaVMInitArgs(&vm_args);
	JavaVMOption options[2];
	options[0].optionString ="-Djava.class.path="USER_CLASSPATH;
	options[1].optionString ="-Djava.library.path="USER_CLASSPATH;
	vm_args.version = JNI_VERSION_1_4;
	vm_args.options = options;
	vm_args.nOptions = 2;
	vm_args.ignoreUnrecognized = JNI_TRUE;

	jint r = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);

	jsize maxNoOfVMs = 1;
	jsize actualNoOfVMs;

	jint response = JNI_GetCreatedJavaVMs(&jvm, maxNoOfVMs, &actualNoOfVMs);
	if (JNI_OK == response && 0 == actualNoOfVMs)
		response = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);

	if(r==-1)
		exit(1);
	else
		cout << "jvm created\n";

	return env;
}

void invoke_class(JNIEnv* env) {
	jclass helloWorldClass;
	jmethodID mainMethod;
	jobjectArray applicationArgs;
	jstring applicationArg0;
	jboolean bE;

	helloWorldClass = env->FindClass("prog");
	cout << "class found\n";
	//mainMethod = env->GetStaticMethodID(helloWorldClass, "main", "([Ljava/lang/String;)V");
	//cout << "static method id found\n";
	//applicationArgs = env->NewObjectArray(1, env->FindClass("java/lang/String"), NULL);
	//applicationArg0 = env->NewStringUTF("Kashif Mushtaq");
	//env->SetObjectArrayElement(applicationArgs, 0, applicationArg0);
	//cout << "SetObjectArrayElement\n";
	//env->CallStaticVoidMethod(helloWorldClass, mainMethod, applicationArgs);
	//cout << "Called CallStaticVoidMethod\n";

	jmethodID validateMethodID = env->GetStaticMethodID(helloWorldClass, "validate", "([Ljava/lang/String;)Ljava/lang/String;");
	bE=env->ExceptionCheck();
	if(bE==JNI_TRUE) {
		cout << "call failed validateMethodID\n";
		env->ExceptionClear();
		exit(0);
	}

	cout << "got validateMethodID\n";
	jobjectArray validateArgs = env->NewObjectArray(1, env->FindClass("java/lang/String"), NULL);
	jstring Args_0 = env->NewStringUTF("Sent from Java as argument");
	env->SetObjectArrayElement(validateArgs, 0, Args_0);

	cout << "calling validateMethodID\n";
	jobject sR=env->CallStaticObjectMethod(helloWorldClass, validateMethodID, validateArgs);
	cout << "called validateMethodID\n";
	bE=env->ExceptionCheck();
	if(bE==JNI_TRUE) {
		cout << "call failed exception\n";
		env->ExceptionClear();
	}
	else {
		char outbuf[1024];
		int len = env->GetStringLength((jstring)sR);
		env->GetStringUTFRegion((jstring)sR, 0, len, outbuf);
		printf("%s", outbuf);

		//get by ref changed array cell value
		jobject jr= env->GetObjectArrayElement(validateArgs,0);
		char outcell[1024];
		int ilen = env->GetStringLength((jstring)jr);
		env->GetStringUTFRegion((jstring)jr, 0, ilen, outbuf);
		printf("%s", outbuf);
	}
}


int main(int argc, char **argv) {
	JNIEnv* env = create_vm();
	invoke_class( env );


	char c[1];
	cout << "Please press q enter to quit";
	cin >> c;
	exit(0);

}