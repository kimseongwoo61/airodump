# airodump 802.11 패킷 분석
## 802.11 Packet parser!!!
기일: January 12, 2023

### 1. 개요

- 해당 코드는 Monitor mode의 무선랜 인터페이스에서 802.11 패킷을 수신 및 분석해주며, 파이썬 기반으로 작성되었습니다.
- 의존 모듈 : socket, sys, os
- 사용법
    
    입력되는 무선랜 인터페이스가 반드시 Monitor mode여야 정상적으로 Sniffing이 가능합니다.
    
    ```bash
    sudo python airodump.py <무선랜 이름>
    ```  
    

  
  
### 2. 유의사항

- 본 파이썬 코드는 별도의 다중 프로세스(또는 스레드) 기반 동작을 진행하지 않기 때문에 airodump 명령어에 비해 reloading 속도가 낮을 수 있습니다.
