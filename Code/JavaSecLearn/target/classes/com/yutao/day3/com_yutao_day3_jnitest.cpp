#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <string>
#include "com_yutao_day3_jnitest.h"

using namespace std;

JNIEXPORT jstring JNICALL Java_com_anbai_sec_cmd_CommandExecution_exec(JNIEnv *env, jclass jclass, jstring str)
{
    printf("jnitest success\n");
    return NULL;
}