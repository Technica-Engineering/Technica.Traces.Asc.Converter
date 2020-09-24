#include <array>
#include <codecvt>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>

#include <Vector/ASC.h>
#include <light_pcapng_ext.h>
#include "endianness.h"

using namespace Vector::ASC;

#define HAS_FLAG(var,pos) ((var) & (1<<(pos)))

#define LINKTYPE_ETHERNET 1 
#define LINKTYPE_CAN_SOCKETCAN 227 

#define DIR_IN    1
#define DIR_OUT   2

class CanFrame {
private:
	uint8_t raw[72] = { 0 };
public:

	uint32_t id() {
		return ntoh32(*(uint32_t*)raw) & 0x1fffffff;
	}

	void id(uint32_t value) {
		uint8_t id_flags = *raw & 0xE0;
		*(uint32_t*)raw = hton32(value);
		*raw |= id_flags;
	}

	bool ext() {
		return (*raw & 0x80) != 0;
	}
	void ext(bool value) {
		uint8_t masked = *raw & 0x7F;
		*raw = masked | value << 7;
	}

	bool rtr() {
		return (*raw & 0x40) != 0;
	}
	void rtr(bool value) {
		uint8_t masked = *raw & 0xBF;
		*raw = masked | value << 6;
	}

	bool err() {
		return (*raw & 0x20) != 0;
	}
	void err(bool value) {
		uint8_t masked = *raw & 0xDF;
		*raw = masked | value << 5;
	}

	bool brs() {
		return (*(raw + 5) & 0x01) != 0;
	}
	void brs(bool value) {
		uint8_t masked = *(raw + 5) & 0xFE;
		*(raw + 5) = masked | value << 0;
	}

	bool esi() {
		return (*(raw + 5) & 0x02) != 0;
	}
	void esi(bool value) {
		uint8_t masked = *(raw + 5) & 0xFD;
		*(raw + 5) = masked | value << 1;
	}

	uint8_t len() {
		return *(raw + 4);
	}
	void len(uint8_t value) {
		*(raw + 4) = value;
	}

	const uint8_t* data() {
		return raw + 8;
	}
	void data(const uint8_t* value, size_t size) {
		memcpy(raw + 8, value, size);
	}

	const uint8_t* bytes() {
		return raw;
	}

	const uint8_t size() {
		return len() + 8;
	}

};

template <class ObjHeader>
int write_packet(
	light_pcapng pcapng,
	uint16_t link_type,
	ObjHeader* oh,
	uint32_t length,
	const uint8_t* data,
	uint32_t flags = 0
) {

	light_packet_interface interface = { 0 };
	interface.link_type = link_type;
	interface.name = (char*)std::to_string(oh->channel).c_str();

	uint64_t ts_resol = 100000;

	light_packet_header header = { 0 };
	uint64_t ts = (100000 / ts_resol) * oh->time;
	header.timestamp.tv_sec = ts / 100000;
	header.timestamp.tv_nsec = ts % 100000;

	header.captured_length = length;
	header.original_length = length;

	return light_write_packet(pcapng, &interface, &header, data);
}

// CAN_MESSAGE = 20
void write(light_pcapng outfile, CanMessage* obj) {
	CanFrame can;

	can.id(obj->id);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_EXTENDED_MESSAGE = 21
void write(light_pcapng outfile, CanExtendedMessage* obj) {
	CanFrame can;

	can.id(obj->id);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_REMOTE_FRAME = 22
void write(light_pcapng outfile, CanRemoteFrame* obj) {
	CanFrame can;

	can.id(obj->id);

	can.rtr(true);
	
	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_ERROR_FRAME = 23
void write(light_pcapng outfile, CanErrorFrame* obj) {
	CanFrame can;

	can.id(obj->id);
	can.len(obj->dlc);
	can.err(true);

	uint32_t flags = DIR_IN;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_ERROR = 25
void write(light_pcapng outfile, CanError* obj) {
	CanFrame can;

	can.err(true);

	uint32_t flags = obj->rxErr != 0 ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_OVERLOAD_FRAME = 26
void write(light_pcapng outfile, CanOverloadFrame* obj) {
	CanFrame can;

	can.err(true);

	uint32_t flags = DIR_IN;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_FD_MESSAGE = 30
void write(light_pcapng outfile, CanFdMessage* obj) {
	CanFrame can;
	can.id(obj->id);
	can.esi(obj->esi);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.brs(obj->brs);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_FD_EXTENDED_MESSAGE = 32
void write(light_pcapng outfile, CanFdExtendedMessage* obj) {
	CanFrame can;
	can.id(obj->id);
	can.esi(obj->esi);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.brs(obj->brs);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// CAN_FD_ERROR_FRAME = 33
void write(light_pcapng outfile, CanFdErrorFrame* obj) {
	CanFrame can;
	can.id(obj->id);
	can.esi(obj->esi);
	can.rtr(HAS_FLAG(obj->flags1, 7));
	can.brs(obj->brs);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), flags);
}

// ETHERNET_PACKET = 110
void write(light_pcapng outfile, EthernetPacket* obj) {
	std::vector<uint8_t> eth(obj->data);
	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_ETHERNET, obj, (uint32_t)eth.size(), eth.data(), flags);
}
// ETHERNET_RX_ERROR
void write(light_pcapng outfile, EthernetRxError* obj) {
	std::vector<uint8_t> eth(obj->data);

	uint8_t* crcPtr = (uint8_t*)&obj->frameChecksum;
	std::vector<uint8_t> crc(crcPtr, crcPtr + 4);
	eth.insert(eth.end(), crc.begin(), crc.end());

	uint32_t flags = DIR_IN;

	write_packet(outfile, LINKTYPE_ETHERNET, obj, (uint32_t)eth.size(), eth.data(), flags);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		fprintf(stderr, "Usage %s [infile] [outfile]", argv[0]);
		return 1;
	}
	Vector::ASC::File infile;

	infile.open(argv[1]);
	if (!infile.is_open()) {
		fprintf(stderr, "Unable to open: %s\n", argv[1]);
		return 1;
	}
	light_pcapng outfile = light_pcapng_open(argv[2], "wb");
	if (!outfile) {
		fprintf(stderr, "Unable to open: %s\n", argv[2]);
		return 1;
	}
	while (!infile.eof()) {
		Event* ohb = nullptr;

		/* read and capture exceptions, e.g. unfinished files */
		try {
			ohb = infile.read();
		}
		catch (std::exception& e) {
			std::cout << "Exception: " << e.what() << std::endl;
		}
		if (ohb == nullptr) {
			break;
		}
		/* Object */
		switch (ohb->eventType) {
		case Event::EventType::CanMessage:
			write(outfile, reinterpret_cast<CanMessage*>(ohb));
			break;
		case Event::EventType::CanExtendedMessage:
			write(outfile, reinterpret_cast<CanExtendedMessage*>(ohb));
			break;
		case Event::EventType::CanRemoteFrame:
			write(outfile, reinterpret_cast<CanRemoteFrame*>(ohb));
			break;
		case Event::EventType::CanErrorFrame:
			write(outfile, reinterpret_cast<CanErrorFrame*>(ohb));
			break;
		case Event::EventType::CanError:
			write(outfile, reinterpret_cast<CanError*>(ohb));
			break;
		case Event::EventType::CanOverloadFrame:
			write(outfile, reinterpret_cast<CanOverloadFrame*>(ohb));
			break;
		case Event::EventType::CanFdMessage:
			write(outfile, reinterpret_cast<CanFdMessage*>(ohb));
			break;
		case Event::EventType::CanFdExtendedMessage:
			write(outfile, reinterpret_cast<CanFdExtendedMessage*>(ohb));
			break;
		case Event::EventType::CanFdErrorFrame:
			write(outfile, reinterpret_cast<CanFdErrorFrame*>(ohb));
			break;
		case Event::EventType::EthernetPacket:
			write(outfile, reinterpret_cast<EthernetPacket*>(ohb));
			break;
		case Event::EventType::EthernetRxError:
			write(outfile, reinterpret_cast<EthernetRxError*>(ohb));
			break;
		}
	}
}