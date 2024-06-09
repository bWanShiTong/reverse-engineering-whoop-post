# Reverse Engineering Whoop 4.0 for fun and FREEDOM

Subscription services hate them or loathe them, they sadly exist. More and more companies move towards them, it started with paying for subscription to watch movies and tv-shows on Netflix, then free services added subscriptions to not show ads, and then companies that sell physical devices started adding subscriptions to use them.

BMW wanted to include them heated seats but after backlash they dropped it. But many companies have them like [8sleep](https://www.eightsleep.com/), they sleep mattress for 2500$ and then require subscription services to use it. But no company has went further in this business model than [Whoop](https://www.whoop.com/). They don't even "sell" their device, but sell member ship for either a year or 2 years and you get device for "free".

### More reasons

Whoop has few sensors: heart rate sensor, temperature and for blood oxygen, but temperature and blood oxygen is only measured once a day, during sleep. It's alarm can only be set to ring only once a day, instead of for multiple periods.

## How?

First step is general reconnaissance, how does device communicate with app, what happens on device and what happens on phone...

What can device do:

- [x] Measure heart rate
- [ ] Measure blood oxygen
- [ ] Measure temperature
- [ ] Store and retrieve data
- [x] Vibrate as alarm

Let's see what can we learn from device with [BLE scanner](https://play.google.com/store/apps/details?id=com.macdom.ble.blescanner&hl=en_US)

![BLE scanner](./src/blescanner.jpeg)

We can see it has heart rate service, which means without any additional reverse engineering we can get heart rate from device. We can assume most of data between device and app is exchange using `CUSTOM SERVICE`. This service has few characteristics:

| Characteristics   | Name              | Writable  | Readable  | Notifiable    | Handle    |
| :---------------- | :---------------- | :-------: | :-------: | :--------:    | :-------: |
| 0x61080002        | CMD_TO_STRAP      | +         | -         | -             | 0x0010    |
| 0x61080003        | CMD_FROM_STRAP    | -         | -         | +             | 0x0012    |
| 0x61080004        | EVENTS_FROM_STRAP | -         | -         | +             | 0x0015    |
| 0x61080005        | DATA_FROM_STRAP   | -         | -         | +             | 0x0018    |
| 0x61080007        | MEMFAULT          | -         | -         | +             | 0x001b    |

(Names were gotten from decompiled apk)

Since `CMD_TO_STRAP` is only writable characteristic, and it's name is `CMD_TO_STRAP` we can assume it is used to send commands to device.

How can we see what data is sent to device, there are multiple methods to do this:

First is using [adb](https://developer.android.com/tools/adb) bugreport to do this you first must enable it in `Developer Settings` under `Bluetooth HCI snoop logging`.

Bluetooth HCI logs can be extracted with following commands:
```sh
adb bugreport logs
unzip logs.zip
wireshark FS/data/log/bt/btsnoop_hci.log 
```

This is good way to extract many logs and then extract data from them to check for correctness and get information being used but I prefer using wireshark directly on device while using app, to do this enable connect phone to compute and check if `adb` can see it using:
```sh
adb devices -l
```

I you see your device then it is connected after that just run [`wireshark`](https://www.wireshark.org/), sudo is required
```sh
sudo wireshark
```

![wireshark](./src/wireshark.png)

Select `Android Bluetooth Btsnoop ...`

After that filter for packets that use `Bluetooth Attribute Protocol` with `btatt`. Now that we only see `btatt` packages go over app and you will see data getting exchanged between device and phone.

### Opening app

After opening app we can see following in wireshark:

![wireshark open app](./src/wireshark-open.png)

We can see that app sends data to device using `CMD_TO_STRAP`, then we receive one notification on `CMD_FROM_STRAP` and many notifications on `DATA_FROM_STRAP`

Data being sent to `CMD_TO_STRAP` is 

```
aa0800a823461600699b4cfb
```

Before we look at data being sent from device let's try to see what data we send to device. To help we can add filter `btatt.handle == 0x10`

In order to test commands let's try to connect to device from computer.

## Connecting to device

There are multiple way to connect to device both from phone and from your computer. Some of them are: [`hcitool`](https://linux.die.net/man/1/hcitool) and [`gatttool`](https://manpages.debian.org/unstable/bluez/gatttool.1.en.html), but I prefer using python and `pygatt`. 

Scanning for devices:
```py
from pygatt import GATTToolBackend, BLEAddressType

adapter = GATTToolBackend(hci_device='hci0')
adapter.start()

for device in adapter.scan(timeout=5):
    print(device)
```


This will scan for devices for 5 seconds and print them out, to connect to device:
```py
device = adapter.connect('XX:XX:XX:XX:XX:XX', address_type=BLEAddressType.random)
```

### Alarm

Let's go to app and set alarm to time and see what data device sends:
```
aa10005723  6d  4201    d0366566    00000000    f62deb81 # 7:00 Exact time
aa10005723  6e  4201    0c376566    00000000    1023ccef # 7:01 Exact time
aa10005723  6f  4201    207d6566    00000000    fea1e060 # 12:00 Exact time
aa10005723  70  4201    50116566    00000000    f226a8bd # 4:20 Exact time
aa10005723  81  4201    f07e6666    00000000    7037c2a4 # Peak 06:20
aa10005723  82  4201    f07e6666    00000000    7151203d # Perform 06:20
aa10005723  83  4201    f07e6666    00000000    b18eaefc # In the Green 06:20
```

Let's examine packages sent:

* First 5 bytes are package header: `aa10005723`
* Next byte seems to be some package count it increments by 1 every time
* Next 2 bytes are same on all packages so they might be some flags
* Next 4 bytes are unix timestamp that corresponds to next time alarm needs to ring
* Next 8 bytes seem to be padding
* Next 8 bytes seem to be checksum

It seems that sleep goal is handled on phone, and if sleep is in green range alarm new alarm time gets sent to device. Now let's try to set alarm to ring in 10 seconds. First let's see if it checks package count and checksum

```py
unix_time = int(time.time()) + 10
unix = struct.pack('<I', unix_time).hex()

package = f"aa10005723704201{unix}00000000f226a8bd"

device.char_write("61080002-8d6d-82b8-614a-1c8cb0f8dcc6", bytearray.fromhex(package), wait_for_response=False)
```

And it doesn't work, now let's see what kind of checksum is used:

```
aa100057236d4201d036656600000000    f62deb81
aa100057236e42010c37656600000000    1023ccef
aa100057236f4201207d656600000000    fea1e060
aa100057237042015011656600000000    f226a8bd
```

#### Simple Solution

Go to [crccalc.com](https://crccalc.com/) and paste data and select `hex` for Input and `CRC-32`

![CRC Calc](./src/crccals.png)

And no luck, let's try to reverse engineer checksum, [@colinoflynn](https://github.com/colinoflynn) created a python package to reverse engineer CRCs [crcbeagle](https://github.com/colinoflynn/crcbeagle) so first clone it and enter it:
```sh
git clone https://github.com/colinoflynn/crcbeagle
cd crcbeagle
touch examine.py
```

And copy following script to `examine.py`, in your example put your packages in data

```py
from crcbeagle.crcbeagle import CRCBeagle

crc = CRCBeagle()

def hex_to_int(hex):
    return [i for i in bytearray.fromhex(hex)]

data = """
aa100057236d4201d036656600000000f62deb81
aa100057236e42010c376566000000001023ccef
aa100057236f4201207d656600000000fea1e060
aa100057237042015011656600000000f226a8bd
""".split('\n')

data = [i for i in data if i]
checksums = [i[len(i) - 8:] for i in data]
data = [i[:len(i) - 8] for i in data]


crc.search(
    [hex_to_int(i) for i in data],
    [hex_to_int(i) for i in checksums]
)
```

Output provides code for checksums:
```py
import struct
from crccheck.crc import Crc32Base
crc = Crc32Base
def my_crc(message):
    crc._poly = 0x4C11DB7
    crc._reflect_input = True
    crc._reflect_output = True
    crc._initvalue = 0x0
    crc._xor_output = 0xF43F44AC
    output_int = crc.calc(message)
    output_bytes = struct.pack("<I", output_int)
    output_list = list(output_bytes)
    return (output_int, output_bytes, output_list)

m = [170, 16, 0, 87, 35, 109, 66, 1, 208, 54, 101, 102, 0, 0, 0, 0]
output = my_crc(m)
print(hex(output[0]))
```

Now let's add checksum to package we send:

```py
package = f"aa10005723704201{unix}00000000"
checksum = my_crc(bytearray.fromhex(package))
package = f"{package}{checksum}"

device.char_write("61080002-8d6d-82b8-614a-1c8cb0f8dcc6", bytearray.fromhex(package), wait_for_response=False)
```

And no go, sometimes is throws error and sometimes it just doesn't, so it is possible that this is error sending and our package is good, so let's send data from [BLE scanner](https://play.google.com/store/apps/details?id=com.macdom.ble.blescanner&hl=en_US)

![Sending alarm](./src/sending-alarm.jpg)

And it works. So why it doesn't work with computer, i don't know... I have tried to do it with another library [`bleak`](https://github.com/hbldh/bleak), and it doesn't work, so next try is with [`gatttool`](https://manpages.debian.org/unstable/bluez/gatttool.1.en.html):

```sh
sudo gatttool -i hci0 -t random -b XX:XX:XX:XX:XX:XX --char-write -a 0x0010 -n aa10005723704201126d6566000000003d59d8fd
```

And this "works", it works randomly but it is good enough for me.

### Broadcast heart rate

With wireshark opened, toggle `BROADCAST HEART RATE`, these are packages sent:
```
aa0800a823070e00c7e40f08 # Off
aa0800a823080e016c935474 # On
aa0800a823090e00cdc99102 # Off
```

After running [`enable_notifications.py`](https://github.com/hbldh/bleak/blob/develop/examples/enable_notifications.py) with notifications off:
```sh
python3 enable_notifications.py --address XX:XX:XX:XX:XX:XX 00002a37-0000-1000-8000-00805f9b34fb
```

It gets `ERROR: could not find device with address 'XX:XX:XX:XX:XX:XX'`, but after having notifications enabled it connects and prints heart rate, so after running:

```sh
sudo gatttool -i hci0 -t random -b XX:XX:XX:XX:XX:XX --char-write -a 0x0010 -n aa0800a823070e00c7e40f08
```

and rerunning `enable_notifications.py` it fails, and after running it works:

```sh
sudo gatttool -i hci0 -t random -b XX:XX:XX:XX:XX:XX --char-write -a 0x0010 -n aa0800a823080e016c935474
```

This means that packet count is not checked and used at all.

### Start activity

After starting activity packet gets sent and after it notifications on `DATA_FROM_STRAP` get received every second. These packages have same header and format as packages for [Broadcast heart rate](#broadcast-heart-rate).

```
aa0800a823  8c  03  01  7d5ec627 # Starting
aa0800a823  8d  03  00  dc040351 # Exiting
aa0800a823  90  03  01  6904fa32 # Start
aa0800a823  91  03  00  c85e3f44 # Exit
aa0800a823  8f  03  00  b2d08752 # Sleep start
aa0800a823  07  0e  00  c7e40f08 # Heart Rate Broadcast Off
aa0800a823  08  0e  01  6c935474 # Heart Rate Broadcast On
aa0800a823  09  0e  00  cdc99102 # Heart Rate Broadcast Off
aa0800a823  05  03  00  e44e25be # Health Monitor off
aa0800a823  06  03  01  2bc064cb # Health Monitor on
aa0800a823  5a  16  00  7dc170ee # Sleep start
aa0800a823  5f  16  00  9603bbe8 # Sleep start (This gets periodically sent during sleep)
aa0800a823  66  74  01  3ae4cde3 # -||-
aa0800a823  91  45  01  dd861b95 # Alarm off
aa0800a823  0e  16  00  1147c585 # This command seems to retrieve data
```

Packet structure

1. First 5 bytes are header
2. Next byte is packet count
3. Next byte is category:
    * `0e` for Broadcast heart rate
    * `03` for activity
    * `16` for sleep start
    * `74` gets sent during sleep, not sure what
    * `45` alarm off
4. Next byte is on/off 
5. Last 4 bytes are checksum

After listening on `DATA_FROM_STRAP` with

```sh
python3 enable_notifications.py --address XX:XX:XX:XX:XX:XX 61080005-8d6d-82b8-614a-1c8cb0f8dcc6
```

And running:

```sh
sudo gatttool -i hci0 -t random -b XX:XX:XX:XX:XX:XX --char-write -a 0x0010 -n aa0800a8238c03017d5ec627
```

We receive notification every second and after running, they stop:

```sh
sudo gatttool -i hci0 -t random -b XX:XX:XX:XX:XX:XX --char-write -a 0x0010 -n aa0800a8238d0300dc040351
```

This is data received after starting activity:

```
Header          Unix        S       HR  RR  RR data                 Checksum
aa1800ff2802    ad896566    f065    42  01  67060000000000000101    3ba00d4d
aa1800ff2802    ae896566    f860    43  00  00000000000000000101    5025f793
aa1800ff2802    af896566    085c    42  00  00000000000000000101    add7df13
aa1800ff2802    b0896566    1057    42  00  00000000000000000101    24b22179
aa1800ff2802    b1896566    1852    42  00  00000000000000000101    e0a905b8
aa1800ff2802    b2896566    284d    42  00  00000000000000000101    d943226a
aa1800ff2802    b3896566    3848    43  00  00000000000000000101    28364865
aa1800ff2802    b4896566    4043    43  00  00000000000000000101    9c2e99ba
aa1800ff2802    b5896566    503e    43  00  00000000000000000101    ebb8a1ce
aa1800ff2802    b6896566    5039    43  00  00000000000000000101    d1635459
aa1800ff2802    b7896566    6834    43  00  00000000000000000101    ccefa569
aa1800ff2802    b8896566    702f    43  00  00000000000000000101    8770ff99
aa1800ff2802    b9896566    802a    43  00  00000000000000000101    d2299e02
aa1800ff2802    ba896566    8825    44  00  00000000000000000101    3cd6a988
aa1800ff2802    bb896566    9020    44  00  00000000000000000101    94f13f2f
aa1800ff2802    bc896566    a01b    44  00  00000000000000000101    c8ed7785
aa1800ff2802    bd896566    b016    44  00  00000000000000000101    3b07bb4b
```

These are also same packages that are received when `Health Monitor` gets opened.

### Sleep

During sleep these get sent to Whoop periodically, they have same format as alarm, but instead of `4201` they have `1701`:
```
aa10005723  5b  1701    07a5    000000000000    05eeba82
aa10005723  5c  1701    0ca5    000000000000    d0e7ebf6
aa10005723  5d  1701    11a5    000000000000    ea1cdbd0
aa10005723  5e  1701    16a5    000000000000    f273fc43
aa10005723  60  1701    1aa5    000000000000    a7064f6e
aa10005723  ad  1701    d6a5    000000000000    a8357b29
aa10005723  b8  1701    fca5    000000000000    bf236c9e
aa10005723  be  1701    14a6    000000000000    b5cd0417
```

Bytes 9-10 seem to increment by 5 every time they get sent, with it being `u16` in little endian. After each of these get sent data comes on `DATA_FROM_STRAP`

Part 2 with data retrieval, blood oxygen measuring and temperature measuring coming soon