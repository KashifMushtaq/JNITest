# JNI Test (C++ -> Java)

A small test program to invoke a Java class (in a jar) from C++ using JNI (Java Native Interface)

# JNI Sample (Java -> C++) 
JWrapper.h
JWrapper.cpp




; JWrapper.def : Declares the module parameters for the DLL.

LIBRARY      "JWrapperWin"

EXPORTS
	;For JNI all . in java package changed to _
	; Java Class = JWrapper
	; Native Method = Initialize=
  	; Method name starts with Java_
  	; Java Package = edu.internet2.middleware.idp.authn.provider
	
	Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JWrapper_Initialize

	
	;For Regular C++
	_Initialize
  
  
# Sample Method

JNIEXPORT jint JNICALL Java_edu_internet2_middleware_shibboleth_idp_authn_provider_JWrapper_Initialize(JNIEnv * env, jclass cls)
  
# First argument is always pointer to JNIEnv and then Java Class

JNIEnv * env, jclass cls
  

# Java Native Interface

package edu.internet2.middleware.shibboleth.idp.authn.provider;

public class JWrapper
{

    /**
     * Initialize Call initialize after object creation This procedure is
     * successful returns 1 otherwise returns 0
     *
     * @return 0 | 1
     */
    public native int Initialize();
}
