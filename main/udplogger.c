// (c) 2018-2021 HomeAccessoryKid

#include <stdio.h>
#include <esp_wifi.h>
#include "esp_netif.h"
#include <esp_system.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <lwip/sockets.h>
#include <lwip/raw.h>
#include <udplogger.h>

char udplogstring[2900]={0}; //in the end I do not know to prevent overflow, so I use the max size of 2 UDP packets ??
int  udplogstring_len=0;

void udplog_send(void *pvParameters){
    int lSocket,i=0;
    struct sockaddr_in sLocalAddr, sDestAddr;

//     while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) vTaskDelay(20); //Check if we have an IP every 200ms 
    esp_netif_ip_info_t info;
    esp_netif_t* esp_netif;
    while ((esp_netif=esp_netif_next_unsafe(NULL))==NULL || !esp_netif_is_netif_up(esp_netif) || esp_netif_get_ip_info(esp_netif,&info)!=ESP_OK || info.ip.addr==0) vTaskDelay(20);

    lSocket = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    memset((char *)&sLocalAddr, 0, sizeof(sLocalAddr));
    memset((char *)&sDestAddr,  0, sizeof(sDestAddr));
    /*Destination*/
    sDestAddr.sin_family = AF_INET;
    sDestAddr.sin_len = sizeof(sDestAddr);
    sDestAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sDestAddr.sin_port =28338; //= 45678; //reversed bytes
    /*Source*/
    sLocalAddr.sin_family = AF_INET;
    sLocalAddr.sin_len = sizeof(sLocalAddr);
    sLocalAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    sLocalAddr.sin_port =40109; //= 44444; //reversed bytes
    lwip_bind(lSocket, (struct sockaddr *)&sLocalAddr, sizeof(sLocalAddr));

    while (1) {
        if ((!i && udplogstring_len) || udplogstring_len>700) {
            lwip_sendto(lSocket, udplogstring, udplogstring_len, 0, (struct sockaddr *)&sDestAddr, sizeof(sDestAddr));
            udplogstring_len=0;
            i=10;
        }
        if (!i) i=10; //sends output every 100ms if not more than 700 bytes
        i--;
        vTaskDelay(1); //with len>1000 and delay=10ms, we might handle 800kbps throughput
    }
}

void udplogger_init(int prio) {
    xTaskCreate(udplog_send, "logsend", 4096, NULL, prio, NULL);
}