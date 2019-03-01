#include <jni.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <map>
#include <sys/ioctl.h>
//#include <linux/android_alarm.h>

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "qtfreet00", __VA_ARGS__)


extern "C" {

int i = 0;

char *jstringToChar(JNIEnv *env, jstring jstr) {
    if (jstr == NULL) {
        return NULL;

    }
    char *rtn = new char;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("utf-8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray) env->CallObjectMethod(jstr, mid, strencode);
    jsize alen = env->GetArrayLength(barr);
    jbyte *ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0) {
        rtn = (char *) malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;

    } else {
        rtn = "";

    }

    /**资源清理**/
    env->ReleaseByteArrayElements(barr, ba, 0);
    if (clsstring != NULL) {
        env->DeleteLocalRef(clsstring);
        clsstring = NULL;

    }
    if (strencode != NULL) {
        env->DeleteLocalRef(strencode);
        strencode = NULL;

    }
    mid = NULL;
    return rtn;
}

jstring chartoJstring(JNIEnv *env, const char *pat) {
    jclass strClass = env->FindClass("Ljava/lang/String;");
    jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = env->NewByteArray(strlen(pat));
    env->SetByteArrayRegion(bytes, 0, strlen(pat), (jbyte *) pat);
    jstring encoding = env->NewStringUTF("utf-8");
    return (jstring) env->NewObject(strClass, ctorID, bytes, encoding);
}


jobject getApplication(JNIEnv *env) {
    jclass localClass = env->FindClass("android/app/ActivityThread");
    if (localClass != NULL) {
        jmethodID getapplication = env->GetStaticMethodID(localClass, "currentApplication",
                                                          "()Landroid/app/Application;");
        if (getapplication != NULL) {
            jobject application = env->CallStaticObjectMethod(localClass, getapplication);
            return application;
        }
        return NULL;
    }
    return NULL;
}


char *verifySign(JNIEnv *env) {
    //此处用于获取app签名
    jobject context = getApplication(env);
    jclass activity = env->GetObjectClass(context);
    // 得到 getPackageManager 方法的 ID
    jmethodID methodID_func = env->GetMethodID(activity, "getPackageManager",
                                               "()Landroid/content/pm/PackageManager;");
    // 获得PackageManager对象
    jobject packageManager = env->CallObjectMethod(context, methodID_func);
    jclass packageManagerclass = env->GetObjectClass(packageManager);
    //得到 getPackageName 方法的 ID
    jmethodID methodID_pack = env->GetMethodID(activity, "getPackageName", "()Ljava/lang/String;");
    //获取包名
    jstring name_str = static_cast<jstring>(env->CallObjectMethod(context, methodID_pack));
    // 得到 getPackageInfo 方法的 ID
    jmethodID methodID_pm = env->GetMethodID(packageManagerclass, "getPackageInfo",
                                             "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 获得应用包的信息
    jobject package_info = env->CallObjectMethod(packageManager, methodID_pm, name_str, 64);
    // 获得 PackageInfo 类
    jclass package_infoclass = env->GetObjectClass(package_info);
    // 获得签名数组属性的 ID
    jfieldID fieldID_signatures = env->GetFieldID(package_infoclass, "signatures",
                                                  "[Landroid/content/pm/Signature;");
    // 得到签名数组，待修改
    jobject signatur = env->GetObjectField(package_info, fieldID_signatures);
    jobjectArray signatures = reinterpret_cast<jobjectArray>(signatur);
    // 得到签名
    jobject signature = env->GetObjectArrayElement(signatures, 0);
    // 获得 Signature 类，待修改
    jclass signature_clazz = env->GetObjectClass(signature);
    //获取sign
    jmethodID toCharString = env->GetMethodID(signature_clazz, "toCharsString",
                                              "()Ljava/lang/String;");
    //获取签名字符；或者其他进行验证操作
    jstring signstr = static_cast<jstring>(env->CallObjectMethod(signature, toCharString));
    char *ch = jstringToChar(env, signstr);
    //输入签名字符串，这里可以进行相关验证
    return ch;
}


jstring getDeviceID(JNIEnv *env, jobject instance) {
        return (env)->NewStringUTF("unknown");
//    jobject mContext = getApplication(env);
//    if (mContext == NULL) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jclass cls_context = (env)->FindClass("android/content/Context");
//    if (cls_context == 0) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jmethodID getSystemService = (env)->GetMethodID(cls_context,
//                                                    "getSystemService",
//                                                    "(Ljava/lang/String;)Ljava/lang/Object;");
//    if (getSystemService == 0) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jfieldID TELEPHONY_SERVICE = (env)->GetStaticFieldID(cls_context,
//                                                         "TELEPHONY_SERVICE", "Ljava/lang/String;");
//    if (TELEPHONY_SERVICE == 0) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jobject str = (env)->GetStaticObjectField(cls_context, TELEPHONY_SERVICE);
//    jobject telephonymanager = (env)->CallObjectMethod(mContext,
//                                                       getSystemService, str);
//    if (telephonymanager == 0) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jclass cls_tm = (env)->FindClass("android/telephony/TelephonyManager");
//    if (cls_tm == 0) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jmethodID getDeviceId = (env)->GetMethodID(cls_tm, "getDeviceId",
//                                               "()Ljava/lang/String;");
//    if (getDeviceId == 0) {
//        return (env)->NewStringUTF("unknown");
//    }
//    jstring deviceid;
//        deviceid = static_cast<jstring>((env)->CallObjectMethod(telephonymanager, getDeviceId));
//        if (deviceid == NULL) {
//            return (env)->NewStringUTF("unknown");
//        }
//    char *ch = jstringToChar(env, deviceid);
//    return deviceid;
}

char *getCpuInfo() { //获取cpu型号
    //此处在测试时去判断cpu型号是否是intel core，至强或者奔腾，AMD系列，x86手机cpu型号为intel atom，arm一般为联发科，高通，麒麟等等
    //如是判断为前者，则认为当前环境为模拟器

    char *info = new char[128];
    memset(info, 0, 128);
//    char *res = new char[256];
//    memset(res,0,256);
    char *split = ":";
    char *cmd = "/proc/cpuinfo";
    FILE *ptr;
    if ((ptr = fopen(cmd, "r")) != NULL) {
        while (fgets(info, 128, ptr)) {
            char *tmp = NULL;
            //去掉换行符
            if (tmp = strstr(info, "\n"))
                *tmp = '\0';
            //去掉回车符
            if (tmp = strstr(info, "\r"))
                *tmp = '\0';
            if (strstr(info,
                       "Hardware")) {  //真机一般会获取到hardware，示例：Qualcomm MSM 8974 HAMMERHEAD (Flattened Device Tree)
                strtok(info, split);
                char *s = strtok(NULL, split);
                return s;
            } else if (strstr(info,
                              "model name")) { //测试了一个模拟器，取到的是model_name，示例：Intel(R) Core(TM) i5-4590 CPU @ 3.30GHz
                strtok(info, split);
                char *s = strtok(NULL, split);
                //x86架构的移动处理器为Intel(R) Atom(TM)
                if (strstr(s, "Intel(R) Core(TM)") || strstr(s, "Intel(R) Pentium(R)") ||
                    strstr(s, "Intel(R) Xeon(R)") ||
                    strstr(s, "AMD")) { //分别为最常见的酷睿，奔腾，至强，AMD处理器

                }
                LOGE("the cpu native info is %s", s);
                return s;
            }
        }
    } else {
        LOGE("NULLLLLLLLL");
    }
}

char *
getVersionInfo() {
//获取设备版本，真机示例：Linux version 3.4.0-cyanogenmod (ls@ywk) (gcc version 4.7 (GCC) ) #1 SMP PREEMPT Tue Apr 12 11:38:13 CST 2016
// 海马玩：   Linux version 3.4.0-qemu+ (droid4x@CA) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #25 SMP PREEMPT Tue Sep 22 15:50:48
    //腾讯模拟器中包含了tencent字眼
    char *info = new char[256];
    memset(info, 0, 256);
    char *cmd = "/proc/version";
    FILE *ptr;
    if ((ptr = fopen(cmd, "r")) != NULL) {
        while (fgets(info, 256, ptr)) {
            char *tmp = NULL;
            if (tmp = strstr(info, "\n"))
                *tmp = '\0';
            //去掉回车符
            if (tmp = strstr(info, "\r"))
                *tmp = '\0';
            //包含qemu+或者tencent均为模拟器
            LOGE("the kernel info is %s", info);
            return info;
        }
    } else {
        LOGE("NULLLLLLLLL");
        return NULL;
    }
}

void antiFile(const char *res) {
    struct stat buf;
    int result = stat(res, &buf) == 0 ? 1 : 0;
    if (result) {
        LOGE("%s  exsits, emulator!", res);
        //     kill(getpid(),SIGKILL);
        i++;
    }
}

void antiProperty(const char *res) {
    char buff[PROP_VALUE_MAX];
    memset(buff, 0, PROP_VALUE_MAX);
    int result =
            __system_property_get(res, (char *) &buff) > 0 ? 1 : 0; //返回命令行内容的长度
    if (result != 0) {
        LOGE("%s %s  exsits, emulator!", res, buff);
        //  kill(getpid(),SIGKILL);
        i++;
    }
}

void antiPropertyValueContains(const char *res,const char *val) {
    char buff[PROP_VALUE_MAX + 1];
    memset(buff, 0, PROP_VALUE_MAX + 1);
    int lman = __system_property_get(res, buff);
    if (lman > 0) {
        if (strstr(buff, val) != NULL) { // match!
            LOGE("%s property value contains %s . Emulator!", res, val);
            i++;
        }
    }
}

void getDeviceInfo() {
    char buff[PROP_VALUE_MAX];
    memset(buff, 0, PROP_VALUE_MAX);
    __system_property_get("ro.product.name", (char *) &buff);
    LOGE("the model name is %s", buff);
    if (!strcmp(buff, "ChangWan")) {
        //  kill(getpid(),SIGKILL);

    } else if (!strcmp(buff, "Droid4X")) {                     //非0均为模拟器
        //  kill(getpid(),SIGKILL);
    } else if (!strcmp(buff, "lgshouyou")) {
        // kill(getpid(),SIGKILL);
    } else if (!strcmp(buff, "nox")) {
        //  kill(getpid(),SIGKILL);
    } else if (!strcmp(buff, "ttVM_Hdragon")) {
        //  kill(getpid(),SIGKILL);
    }

}


char *SocketTest(char *c) {
    struct sockaddr_in serv_addr;
    char buff[1024];
    char res[4096];
    memset(res, 0, 4096);
    memset(buff, 0, 1024);
    memset(&serv_addr, 0, sizeof(serv_addr));

    char *addr = "107.151.180.166";
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd == -1) {
        LOGE("create error");
        LOGE("error (errno=%d)", errno);
        exit(1);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(6666);
    serv_addr.sin_addr.s_addr = inet_addr(addr);
    if (serv_addr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *host = gethostbyname(addr);
        if (host == NULL) {
            LOGE("error (errno=%d)", errno);
            exit(1);
        }
        serv_addr.sin_addr.s_addr = ((struct in_addr *) host->h_addr)->s_addr;
    }
    memset(serv_addr.sin_zero, 0, sizeof(serv_addr.sin_zero));
    int conn = connect(socketfd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr));
    if (conn == -1) {
        LOGE("connect error");
        LOGE("error (errno=%d)", errno);
        exit(1);
    }
    int sen = send(socketfd, c, strlen(c), 0);
    if (sen == -1) {
        LOGE("send errorrr");
        LOGE("error (errno=%d)", errno);
        exit(1);
    }
    while (recv(socketfd, buff, 1023, 0) > 0) {
        LOGE("%s", buff);
        strcpy(res, buff);
    }
    close(socketfd);
    LOGE("send successssss");
    return res;

}

/*逍遥模拟器
 * 12-13 12:20:58.671 1615-1615/? E/qtfreet00: the /system/bin/microvirt-prop is exist
12-13 12:20:58.671 1615-1615/? E/qtfreet00: the /system/bin/microvirtd is exist
12-13 12:20:58.671 1615-1615/? E/qtfreet00: the init.svc.vbox86-setup result is stopped
12-13 12:20:58.671 1615-1615/? E/qtfreet00: the init.svc.microvirtd result is running*/

jint check(JNIEnv *env, jobject instance) {

    antiFile("/system/bin/qemu_props"); //检测原生模拟器
    // antiFile("/system/bin/qemud");  //小米会检测出此项
    antiFile("/system/bin/androVM-prop");
    antiFile("/system/bin/microvirt-prop");//逍遥
    antiFile("/system/lib/libdroid4x.so"); //海马玩
    antiFile("/system/bin/windroyed");//文卓爷
    antiFile("/system/bin/microvirtd");//逍遥
    antiFile("/system/bin/nox-prop"); //夜神
    antiFile("/system/bin/ttVM-prop"); //天天
    antiFile("/system/bin/droid4x-prop"); //海马玩
    antiFile("/data/.bluestacks.prop");//bluestacks
    antiProperty("init.svc.vbox86-setup"); //基于vitrualbox
    antiProperty("init.svc.droid4x"); //海马玩
    antiProperty("init.svc.qemud");
    antiProperty("init.svc.su_kpbs_daemon");
    antiProperty("init.svc.noxd"); //夜神
    antiProperty("init.svc.ttVM_x86-setup"); //天天
    antiProperty("init.svc.xxkmsg");
    antiProperty("init.svc.microvirtd");//逍遥
//    antiProperty("ro.secure");   //检测selinux是否被关闭，一般手机均开启此选项
    antiProperty("ro.kernel.android.qemud");
    //  antiProperty("ro.kernel.qemu.gles"); //三星SM-G5500误报此项
    antiProperty("androVM.vbox_dpi");
    antiProperty("androVM.vbox_graph_mode");
    antiPropertyValueContains("ro.product.manufacturer",
                              "Genymotion"); // Genymotion check ,thx alinbaturn
    return i;
}

jstring getCpuinfo(JNIEnv *env, jobject instance) {

    char *res = getCpuInfo();

    return env->NewStringUTF(res);
}

jstring getKernelVersion(JNIEnv *env, jobject /* this */) {

    char *res = getVersionInfo();

    return env->NewStringUTF(res);
}

jstring getApkSign(JNIEnv *env, jobject /* this */) {

    char *res = verifySign(env);

    return env->NewStringUTF(res);
}

//行结束判断...
bool str_end_with(const char *line,int line_len,const char *token)
{
    if(line_len<=0)
        line_len = strlen(line);
    int ref_len = strlen(token);
    if(line_len>=ref_len && memcmp(line+line_len-ref_len,token,ref_len) == 0)
        return true;
    return false;
}

bool str_start_with(const char *line,int line_len,const char *token)
{
    if(line_len<=0)
        line_len = strlen(line);
    int ref_len = strlen(token);
    if(line_len>=ref_len && memcmp(line,token,ref_len) == 0)
        return true;
    return false;
}

//是否需要忽略...
bool ignore_map_line(const char *line)
{
    if(line[0] == '[')
        return true;
    if(line[0] == '\n')
        return true;
    if(line[0] == '\0')
        return true;
    int line_len = strlen(line);
    ///system/fonts/
    if(str_end_with(line,line_len,".ttf"))
        return true;
    if(str_end_with(line,line_len,".ttc"))
        return true;

#if true
    if(str_end_with(line,line_len,"(deleted)"))
        return true;
    if(str_end_with(line,line_len,".art"))
        return true;
    if(str_end_with(line,line_len,".oat"))
        return true;
    if(str_end_with(line,line_len,".apk"))
        return true;

    if(str_end_with(line,line_len,".dat"))
        return true;
    if(str_end_with(line,line_len,".vdex"))
        return true;
    if(str_end_with(line,line_len,".odex"))
        return true;
    if(str_end_with(line,line_len,".dex"))
        return true;
    if(str_end_with(line,line_len,":s0"))
        return true;

    if(str_start_with(line,line_len,"/dev/kgsl-3d0"))
        return true;
    if(str_start_with(line,line_len,"/dev/__properties__"))
        return true;

    //Ashmem(Anonymous Shared Memory 匿名共享内存)，是在 Android 的内存管理中提供的一种机制。mmap系统调用...
    if(str_start_with(line,line_len,"/dev/ashmem/"))//dalvik
        return true;
    if(str_start_with(line,line_len,"/system/lib"))
        return true;
    if(str_start_with(line,line_len,"/system/vendor/lib"))
        return true;
//    if(str_start_with(line,line_len,"/system/lib/android"))
//        return true;
//    if(str_start_with(line,line_len,"/system/lib/vndk-sp"))
//        return true;
    if(str_start_with(line,line_len,"/system/bin/linker"))
        return true;
    if(str_start_with(line,line_len,"/system/fonts"))
        return true;        
    if(str_start_with(line,line_len,"/system/bin/app_"))///system/bin/app_process64
        return true;
    if(str_start_with(line,line_len,"/system/framework/"))
        return true;
    if(str_start_with(line,line_len,"/vendor/lib"))
        return true;
    if(str_start_with(line,line_len,"/dev/binder"))
        return true;
    if(str_start_with(line,line_len,"/system/usr/"))
        return true;
    if(str_start_with(line,line_len,"/product/lib"))
        return true;
    if(str_start_with(line,line_len,"/dev/mali0"))
        return true;
    if(str_start_with(line,line_len,"anon_inode:"))
        return true;

    if(str_end_with(line,line_len,"/event-log-tags"))
        return true;
    if(str_end_with(line,line_len,"/zz.mmap2"))
        return true;
    if(str_end_with(line,line_len,"/libstlport_shared.so"))
        return true;
    if(str_end_with(line,line_len,"/libmono.so"))
        return true;
    if(str_end_with(line,line_len,"/libnative-lib.so"))
        return true;
    if(str_end_with(line,line_len,"/libxlog.so"))
        return true;
    if(str_end_with(line,line_len,"/lib360Nt.so"))
        return true;
    if(str_end_with(line,line_len,"/lib360Pay.so"))
        return true;
    if(str_end_with(line,line_len,"/libBlueDoveMediaRender.so"))
        return true;
    if(str_end_with(line,line_len,"/libBugly.so"))
        return true;
    if(str_end_with(line,line_len,"/libgamemaster.so"))
        return true;
    if(str_end_with(line,line_len,"/libil2cpp.so"))
        return true;
    if(str_end_with(line,line_len,"/libulua.so"))
        return true;
    if(str_end_with(line,line_len,"/libunity.so"))
        return true;
    if(str_end_with(line,line_len,"/libyoume_voice_engine.so"))
        return true;
    if(str_end_with(line,line_len,"/libzlib.so"))
        return true;
    if(str_end_with(line,line_len,"/libmain.so"))
        return true;
#endif
    return false;
}

typedef unsigned char _BYTE;
void dump_module_map(pid_t pid,std::string &buf)
{
    FILE* fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if(pid<0){
        snprintf(filename,sizeof(filename),"/proc/self/maps",pid);
    }else{
        snprintf(filename,sizeof(filename),"/proc/%d/maps",pid);
    }
    fp = fopen(filename,"r");
    if(fp!=NULL){

        std::map<std::string,int> MapStrings;
        int v19; // [sp+38h] [bp-DB8h]@12
        int v20; // [sp+3Ch] [bp-DB4h]@12
        int v21; // [sp+40h] [bp-DB0h]@12
        _BYTE v22[4]; // [sp+44h] [bp-DACh]@12
        //_BYTE v23[3]; // [sp+45h] [bp-DABh]@12
        int v24; // [sp+48h] [bp-DA8h]@12
        int v25; // [sp+4Ch] [bp-DA4h]@12
        int v26; // [sp+50h] [bp-DA0h]@12

        char v31[0x400]; // [sp+9D4h] [bp-41Ch]@12
        while(fgets(line,sizeof(line),fp))
        {
            if ( sscanf(line, "%x-%x %c%c%c%c %x %x:%x %u%s",
                    &v19, &v20,&v22[0], &v22[1], &v22[2], &v22[3],&v21, &v25,&v26,&v24,v31) == 11 )
            {
                if(ignore_map_line(v31))
                {
                }
                else
                {
                    std::string key = v31;
                    //MapStrings.add
                    MapStrings[key] = 1;
                    //buf.append(v31);
                    //buf.append(";");
                    //LOGE("%s",v31);
                }
            }

        }
        fclose(fp);
        LOGE("MapStrings:%d\n",MapStrings.size());
        std::map<std::string,int>::iterator itr = MapStrings.begin();
        for(;itr!=MapStrings.end();++itr)
        {
            //LOGE("%s",itr->first.c_str());
            buf.append(itr->first.c_str());
            buf.append(";");
        }
    }
}


//取得进程中的so等信息
int getInMaps(char *buf,int buf_len)
{
    std::string s;
    dump_module_map(getpid(),s);
    int len = s.length();
    if(buf_len>len && buf)
    {
        memcpy(buf,s.c_str(),len);
        buf[len] = 0;
        return len;
    }
    return 0;
}


jstring getProcessMaps(JNIEnv *env, jobject instance) {

    std::string s;
    dump_module_map(getpid(),s);

    return env->NewStringUTF(s.c_str());
}



static const char *gClassName = "com/qtfreet/anticheckemulator/emulator/JniAnti";
static JNINativeMethod gMethods[] = {
        {"getApkSign",       "()Ljava/lang/String;", (void *) getApkSign},
        {"getKernelVersion", "()Ljava/lang/String;", (void *) getKernelVersion},
        {"getCpuinfo",       "()Ljava/lang/String;", (void *) getCpuinfo},
        {"getDeviceID",      "()Ljava/lang/String;", (void *) getDeviceID},
        {"getProcessMaps",      "()Ljava/lang/String;", (void *) getProcessMaps},
        {"checkAntiFile",    "()I",                  (void *) check},
};

static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

typedef long long __int64;
typedef unsigned char BYTE;
typedef unsigned short WORD;
#define MSG_OP(size,opcode,subcode)\
	char test[size];\
	*((WORD *)(&test[2])) = opcode;\
	*((WORD *)(&test[4])) = subcode;

#define _INTSIZEOF(n)          ((sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1))

#define __crt_va_start_a(ap, v) ((void)(ap = (va_list)_ADDRESSOF(v) + _INTSIZEOF(v)))
#define __crt_va_arg(ap, t)     (*(t*)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)))
#define __crt_va_end(ap)        ((void)(ap = (va_list)0))


// MSG_PRINTF_SEND added by zhaojun 10-15
int MSG_PRINTF_SEND(WORD opcode, WORD subcode, const char* szFormat, ...)
{
    MSG_OP(2048, opcode,0);

    char* pHeader = test;
    char* pAttachHeader = pHeader + 6;
//	short iOffset = 0;

    *((WORD*)(pHeader + 4)) = subcode;

    va_list argptr;
    va_start(argptr, szFormat);

//	if(szFormat)
    while(*szFormat != 0)
    {
        // 有格式化参数
        if (*szFormat != '%')
        {
            *(pAttachHeader++) = *(szFormat++);
        }
        else
        {
            // 特殊符号
            size_t		nDataLen = 0;
            size_t		nOffset = 0;
#ifdef _WIN32
            char* str = (char*)(argptr);
#else
            char* str = va_arg(argptr, char*);
#endif
            void*		target = str;
            switch(*(szFormat + 1))
            {
                case 's':	//以0或者长度约束结束的字符串；
                {
                    //if(argptr == NULL)
                    //{
                    //	assert(false);
                    //	DevLog("[%s][%d] argptr == NULL.\n",__FUNCTION__,__LINE__);
                    //	return 0;
                    //}
#ifdef _WIN32
                    str = (char*)(*((DWORD*)argptr));
#endif
                    nDataLen = strlen(str);
                    if (*(szFormat + 2) != '\0')
                    {
                        ++nDataLen;	//末尾的字符串不需要加分隔符0
                    }
                    nOffset = _INTSIZEOF(const char*);
                    target = str;
                }
                    break;
                case 'a':
                {
                    //if(argptr == NULL)
                    //{
                    //	assert(false);
                    //	DevLog("[%s][%d] argptr == NULL.\n",__FUNCTION__,__LINE__);
                    //	return 0;
                    //}
                    //char* str = (char*)(*((DWORD*)argptr));
                    nDataLen = strlen(str);
                    //不加0，字符串直接有关键字分割
                    nOffset = _INTSIZEOF(const char*);
                    target = str;
                }
                    break;
                case 'S':	//BSTR字符串；
                {
                    //if(argptr == NULL)
                    //{
                    //	assert(false);
                    //	DevLog("[%s][%d] argptr == NULL.\n",__FUNCTION__,__LINE__);
                    //	return 0;
                    //}
                    //char* str = (char*)(*((DWORD*)argptr));
                    nDataLen = strlen(str);
                    //����WORD
                    {
                        WORD wLen = nDataLen;
                        memcpy(pAttachHeader, &wLen, 2);
                        pAttachHeader += 2;
                    }
                    nOffset = _INTSIZEOF(const char*);
                    target = str;
                }
                    break;
                case 'd':
                    nDataLen = sizeof(int);
                    nOffset = _INTSIZEOF(int);
                    break;
                case 'w':
                    nDataLen = sizeof(WORD);
                    nOffset = _INTSIZEOF(WORD);
                    break;
                case 'b':
                    nDataLen = sizeof(BYTE);
                    nOffset = _INTSIZEOF(BYTE);
                    break;
                case 'L':
                    nDataLen = sizeof(__int64);
                    nOffset = _INTSIZEOF(__int64);
                    break;
                default:
                {
#ifdef _DEBUG
                    throw("not support convert character");
#endif
                }
            }

            memcpy(pAttachHeader, target, nDataLen);
            pAttachHeader += nDataLen;
#ifndef __ANDROID__
            argptr += nOffset;
#endif
            szFormat += 2;
        }
    }
    *((WORD*)pHeader) = pAttachHeader - pHeader;
    //*((WORD*)(pHeader + 4)) = pAttachHeader - pHeader;

    return 1;//g_pGameSession->CallEngineSend(pHeader, pAttachHeader - pHeader, 0);
    //return engine->NET_Send(pHeader, pAttachHeader - pHeader, 0);
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }


    //int len = MSG_PRINTF_SEND(1, 2, "%s%s", "abcd","efgh");
    //目前已知问题，检测/sys/class/thermal/和bluetooth-jni.so不稳定，存在兼容性问题
    getDeviceInfo();

//    std::string buf;
//    dump_module_map(getpid(),buf);
//    LOGE("%s",buf.c_str());

    if (registerNativeMethods(env, gClassName, gMethods,
                              sizeof(gMethods) / sizeof(gMethods[0])) == JNI_FALSE) {
        return -1;
    }

    return JNI_VERSION_1_6;
}
}
