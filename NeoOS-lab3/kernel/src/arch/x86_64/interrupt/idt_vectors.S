# Defines the interrupt routines by IDT entries.
# Errno: 0, trap_num = gate_num.
.section .text
gate0:
	push 0
	push 0
	jmp __handle_trap
gate1:
	push 0
	push 1
	jmp __handle_trap
gate2:
	push 0
	push 2
	jmp __handle_trap
gate3:
	push 0
	push 3
	jmp __handle_trap
gate4:
	push 0
	push 4
	jmp __handle_trap
gate5:
	push 0
	push 5
	jmp __handle_trap
gate6:
	push 0
	push 6
	jmp __handle_trap
gate7:
	push 0
	push 7
	jmp __handle_trap
gate8:
	push 8
	jmp __handle_trap
gate9:
	push 0
	push 9
	jmp __handle_trap
gate10:
	push 10
	jmp __handle_trap
gate11:
	push 11
	jmp __handle_trap
gate12:
	push 12
	jmp __handle_trap
gate13:
	push 13
	jmp __handle_trap
gate14:
  # Page fault: CPU will generate errno for us.
	push 14
	jmp __handle_trap
gate15:
	push 0
	push 15
	jmp __handle_trap
gate16:
	push 0
	push 16
	jmp __handle_trap
gate17:
	push 17
	jmp __handle_trap
gate18:
	push 0
	push 18
	jmp __handle_trap
gate19:
	push 0
	push 19
	jmp __handle_trap
gate20:
	push 0
	push 20
	jmp __handle_trap
gate21:
	push 0
	push 21
	jmp __handle_trap
gate22:
	push 0
	push 22
	jmp __handle_trap
gate23:
	push 0
	push 23
	jmp __handle_trap
gate24:
	push 0
	push 24
	jmp __handle_trap
gate25:
	push 0
	push 25
	jmp __handle_trap
gate26:
	push 0
	push 26
	jmp __handle_trap
gate27:
	push 0
	push 27
	jmp __handle_trap
gate28:
	push 0
	push 28
	jmp __handle_trap
gate29:
	push 0
	push 29
	jmp __handle_trap
gate30:
	push 0
	push 30
	jmp __handle_trap
gate31:
	push 0
	push 31
	jmp __handle_trap
gate32:
	push 0
	push 32
	jmp __handle_trap
gate33:
	push 0
	push 33
	jmp __handle_trap
gate34:
	push 0
	push 34
	jmp __handle_trap
gate35:
	push 0
	push 35
	jmp __handle_trap
gate36:
	push 0
	push 36
	jmp __handle_trap
gate37:
	push 0
	push 37
	jmp __handle_trap
gate38:
	push 0
	push 38
	jmp __handle_trap
gate39:
	push 0
	push 39
	jmp __handle_trap
gate40:
	push 0
	push 40
	jmp __handle_trap
gate41:
	push 0
	push 41
	jmp __handle_trap
gate42:
	push 0
	push 42
	jmp __handle_trap
gate43:
	push 0
	push 43
	jmp __handle_trap
gate44:
	push 0
	push 44
	jmp __handle_trap
gate45:
	push 0
	push 45
	jmp __handle_trap
gate46:
	push 0
	push 46
	jmp __handle_trap
gate47:
	push 0
	push 47
	jmp __handle_trap
gate48:
	push 0
	push 48
	jmp __handle_trap
gate49:
	push 0
	push 49
	jmp __handle_trap
gate50:
	push 0
	push 50
	jmp __handle_trap
gate51:
	push 0
	push 51
	jmp __handle_trap
gate52:
	push 0
	push 52
	jmp __handle_trap
gate53:
	push 0
	push 53
	jmp __handle_trap
gate54:
	push 0
	push 54
	jmp __handle_trap
gate55:
	push 0
	push 55
	jmp __handle_trap
gate56:
	push 0
	push 56
	jmp __handle_trap
gate57:
	push 0
	push 57
	jmp __handle_trap
gate58:
	push 0
	push 58
	jmp __handle_trap
gate59:
	push 0
	push 59
	jmp __handle_trap
gate60:
	push 0
	push 60
	jmp __handle_trap
gate61:
	push 0
	push 61
	jmp __handle_trap
gate62:
	push 0
	push 62
	jmp __handle_trap
gate63:
	push 0
	push 63
	jmp __handle_trap
gate64:
	push 0
	push 64
	jmp __handle_trap
gate65:
	push 0
	push 65
	jmp __handle_trap
gate66:
	push 0
	push 66
	jmp __handle_trap
gate67:
	push 0
	push 67
	jmp __handle_trap
gate68:
	push 0
	push 68
	jmp __handle_trap
gate69:
	push 0
	push 69
	jmp __handle_trap
gate70:
	push 0
	push 70
	jmp __handle_trap
gate71:
	push 0
	push 71
	jmp __handle_trap
gate72:
	push 0
	push 72
	jmp __handle_trap
gate73:
	push 0
	push 73
	jmp __handle_trap
gate74:
	push 0
	push 74
	jmp __handle_trap
gate75:
	push 0
	push 75
	jmp __handle_trap
gate76:
	push 0
	push 76
	jmp __handle_trap
gate77:
	push 0
	push 77
	jmp __handle_trap
gate78:
	push 0
	push 78
	jmp __handle_trap
gate79:
	push 0
	push 79
	jmp __handle_trap
gate80:
	push 0
	push 80
	jmp __handle_trap
gate81:
	push 0
	push 81
	jmp __handle_trap
gate82:
	push 0
	push 82
	jmp __handle_trap
gate83:
	push 0
	push 83
	jmp __handle_trap
gate84:
	push 0
	push 84
	jmp __handle_trap
gate85:
	push 0
	push 85
	jmp __handle_trap
gate86:
	push 0
	push 86
	jmp __handle_trap
gate87:
	push 0
	push 87
	jmp __handle_trap
gate88:
	push 0
	push 88
	jmp __handle_trap
gate89:
	push 0
	push 89
	jmp __handle_trap
gate90:
	push 0
	push 90
	jmp __handle_trap
gate91:
	push 0
	push 91
	jmp __handle_trap
gate92:
	push 0
	push 92
	jmp __handle_trap
gate93:
	push 0
	push 93
	jmp __handle_trap
gate94:
	push 0
	push 94
	jmp __handle_trap
gate95:
	push 0
	push 95
	jmp __handle_trap
gate96:
	push 0
	push 96
	jmp __handle_trap
gate97:
	push 0
	push 97
	jmp __handle_trap
gate98:
	push 0
	push 98
	jmp __handle_trap
gate99:
	push 0
	push 99
	jmp __handle_trap
gate100:
	push 0
	push 100
	jmp __handle_trap
gate101:
	push 0
	push 101
	jmp __handle_trap
gate102:
	push 0
	push 102
	jmp __handle_trap
gate103:
	push 0
	push 103
	jmp __handle_trap
gate104:
	push 0
	push 104
	jmp __handle_trap
gate105:
	push 0
	push 105
	jmp __handle_trap
gate106:
	push 0
	push 106
	jmp __handle_trap
gate107:
	push 0
	push 107
	jmp __handle_trap
gate108:
	push 0
	push 108
	jmp __handle_trap
gate109:
	push 0
	push 109
	jmp __handle_trap
gate110:
	push 0
	push 110
	jmp __handle_trap
gate111:
	push 0
	push 111
	jmp __handle_trap
gate112:
	push 0
	push 112
	jmp __handle_trap
gate113:
	push 0
	push 113
	jmp __handle_trap
gate114:
	push 0
	push 114
	jmp __handle_trap
gate115:
	push 0
	push 115
	jmp __handle_trap
gate116:
	push 0
	push 116
	jmp __handle_trap
gate117:
	push 0
	push 117
	jmp __handle_trap
gate118:
	push 0
	push 118
	jmp __handle_trap
gate119:
	push 0
	push 119
	jmp __handle_trap
gate120:
	push 0
	push 120
	jmp __handle_trap
gate121:
	push 0
	push 121
	jmp __handle_trap
gate122:
	push 0
	push 122
	jmp __handle_trap
gate123:
	push 0
	push 123
	jmp __handle_trap
gate124:
	push 0
	push 124
	jmp __handle_trap
gate125:
	push 0
	push 125
	jmp __handle_trap
gate126:
	push 0
	push 126
	jmp __handle_trap
gate127:
	push 0
	push 127
	jmp __handle_trap
gate128:
	push 0
	push 128
	jmp __handle_trap
gate129:
	push 0
	push 129
	jmp __handle_trap
gate130:
	push 0
	push 130
	jmp __handle_trap
gate131:
	push 0
	push 131
	jmp __handle_trap
gate132:
	push 0
	push 132
	jmp __handle_trap
gate133:
	push 0
	push 133
	jmp __handle_trap
gate134:
	push 0
	push 134
	jmp __handle_trap
gate135:
	push 0
	push 135
	jmp __handle_trap
gate136:
	push 0
	push 136
	jmp __handle_trap
gate137:
	push 0
	push 137
	jmp __handle_trap
gate138:
	push 0
	push 138
	jmp __handle_trap
gate139:
	push 0
	push 139
	jmp __handle_trap
gate140:
	push 0
	push 140
	jmp __handle_trap
gate141:
	push 0
	push 141
	jmp __handle_trap
gate142:
	push 0
	push 142
	jmp __handle_trap
gate143:
	push 0
	push 143
	jmp __handle_trap
gate144:
	push 0
	push 144
	jmp __handle_trap
gate145:
	push 0
	push 145
	jmp __handle_trap
gate146:
	push 0
	push 146
	jmp __handle_trap
gate147:
	push 0
	push 147
	jmp __handle_trap
gate148:
	push 0
	push 148
	jmp __handle_trap
gate149:
	push 0
	push 149
	jmp __handle_trap
gate150:
	push 0
	push 150
	jmp __handle_trap
gate151:
	push 0
	push 151
	jmp __handle_trap
gate152:
	push 0
	push 152
	jmp __handle_trap
gate153:
	push 0
	push 153
	jmp __handle_trap
gate154:
	push 0
	push 154
	jmp __handle_trap
gate155:
	push 0
	push 155
	jmp __handle_trap
gate156:
	push 0
	push 156
	jmp __handle_trap
gate157:
	push 0
	push 157
	jmp __handle_trap
gate158:
	push 0
	push 158
	jmp __handle_trap
gate159:
	push 0
	push 159
	jmp __handle_trap
gate160:
	push 0
	push 160
	jmp __handle_trap
gate161:
	push 0
	push 161
	jmp __handle_trap
gate162:
	push 0
	push 162
	jmp __handle_trap
gate163:
	push 0
	push 163
	jmp __handle_trap
gate164:
	push 0
	push 164
	jmp __handle_trap
gate165:
	push 0
	push 165
	jmp __handle_trap
gate166:
	push 0
	push 166
	jmp __handle_trap
gate167:
	push 0
	push 167
	jmp __handle_trap
gate168:
	push 0
	push 168
	jmp __handle_trap
gate169:
	push 0
	push 169
	jmp __handle_trap
gate170:
	push 0
	push 170
	jmp __handle_trap
gate171:
	push 0
	push 171
	jmp __handle_trap
gate172:
	push 0
	push 172
	jmp __handle_trap
gate173:
	push 0
	push 173
	jmp __handle_trap
gate174:
	push 0
	push 174
	jmp __handle_trap
gate175:
	push 0
	push 175
	jmp __handle_trap
gate176:
	push 0
	push 176
	jmp __handle_trap
gate177:
	push 0
	push 177
	jmp __handle_trap
gate178:
	push 0
	push 178
	jmp __handle_trap
gate179:
	push 0
	push 179
	jmp __handle_trap
gate180:
	push 0
	push 180
	jmp __handle_trap
gate181:
	push 0
	push 181
	jmp __handle_trap
gate182:
	push 0
	push 182
	jmp __handle_trap
gate183:
	push 0
	push 183
	jmp __handle_trap
gate184:
	push 0
	push 184
	jmp __handle_trap
gate185:
	push 0
	push 185
	jmp __handle_trap
gate186:
	push 0
	push 186
	jmp __handle_trap
gate187:
	push 0
	push 187
	jmp __handle_trap
gate188:
	push 0
	push 188
	jmp __handle_trap
gate189:
	push 0
	push 189
	jmp __handle_trap
gate190:
	push 0
	push 190
	jmp __handle_trap
gate191:
	push 0
	push 191
	jmp __handle_trap
gate192:
	push 0
	push 192
	jmp __handle_trap
gate193:
	push 0
	push 193
	jmp __handle_trap
gate194:
	push 0
	push 194
	jmp __handle_trap
gate195:
	push 0
	push 195
	jmp __handle_trap
gate196:
	push 0
	push 196
	jmp __handle_trap
gate197:
	push 0
	push 197
	jmp __handle_trap
gate198:
	push 0
	push 198
	jmp __handle_trap
gate199:
	push 0
	push 199
	jmp __handle_trap
gate200:
	push 0
	push 200
	jmp __handle_trap
gate201:
	push 0
	push 201
	jmp __handle_trap
gate202:
	push 0
	push 202
	jmp __handle_trap
gate203:
	push 0
	push 203
	jmp __handle_trap
gate204:
	push 0
	push 204
	jmp __handle_trap
gate205:
	push 0
	push 205
	jmp __handle_trap
gate206:
	push 0
	push 206
	jmp __handle_trap
gate207:
	push 0
	push 207
	jmp __handle_trap
gate208:
	push 0
	push 208
	jmp __handle_trap
gate209:
	push 0
	push 209
	jmp __handle_trap
gate210:
	push 0
	push 210
	jmp __handle_trap
gate211:
	push 0
	push 211
	jmp __handle_trap
gate212:
	push 0
	push 212
	jmp __handle_trap
gate213:
	push 0
	push 213
	jmp __handle_trap
gate214:
	push 0
	push 214
	jmp __handle_trap
gate215:
	push 0
	push 215
	jmp __handle_trap
gate216:
	push 0
	push 216
	jmp __handle_trap
gate217:
	push 0
	push 217
	jmp __handle_trap
gate218:
	push 0
	push 218
	jmp __handle_trap
gate219:
	push 0
	push 219
	jmp __handle_trap
gate220:
	push 0
	push 220
	jmp __handle_trap
gate221:
	push 0
	push 221
	jmp __handle_trap
gate222:
	push 0
	push 222
	jmp __handle_trap
gate223:
	push 0
	push 223
	jmp __handle_trap
gate224:
	push 0
	push 224
	jmp __handle_trap
gate225:
	push 0
	push 225
	jmp __handle_trap
gate226:
	push 0
	push 226
	jmp __handle_trap
gate227:
	push 0
	push 227
	jmp __handle_trap
gate228:
	push 0
	push 228
	jmp __handle_trap
gate229:
	push 0
	push 229
	jmp __handle_trap
gate230:
	push 0
	push 230
	jmp __handle_trap
gate231:
	push 0
	push 231
	jmp __handle_trap
gate232:
	push 0
	push 232
	jmp __handle_trap
gate233:
	push 0
	push 233
	jmp __handle_trap
gate234:
	push 0
	push 234
	jmp __handle_trap
gate235:
	push 0
	push 235
	jmp __handle_trap
gate236:
	push 0
	push 236
	jmp __handle_trap
gate237:
	push 0
	push 237
	jmp __handle_trap
gate238:
	push 0
	push 238
	jmp __handle_trap
gate239:
	push 0
	push 239
	jmp __handle_trap
gate240:
	push 0
	push 240
	jmp __handle_trap
gate241:
	push 0
	push 241
	jmp __handle_trap
gate242:
	push 0
	push 242
	jmp __handle_trap
gate243:
	push 0
	push 243
	jmp __handle_trap
gate244:
	push 0
	push 244
	jmp __handle_trap
gate245:
	push 0
	push 245
	jmp __handle_trap
gate246:
	push 0
	push 246
	jmp __handle_trap
gate247:
	push 0
	push 247
	jmp __handle_trap
gate248:
	push 0
	push 248
	jmp __handle_trap
gate249:
	push 0
	push 249
	jmp __handle_trap
gate250:
	push 0
	push 250
	jmp __handle_trap
gate251:
	push 0
	push 251
	jmp __handle_trap
gate252:
	push 0
	push 252
	jmp __handle_trap
gate253:
	push 0
	push 253
	jmp __handle_trap
gate254:
	push 0
	push 254
	jmp __handle_trap
gate255:
	push 0
	push 255
	jmp __handle_trap

.section .rodata
.global __idt_vectors
__idt_vectors:
	.quad gate0
	.quad gate1
	.quad gate2
	.quad gate3
	.quad gate4
	.quad gate5
	.quad gate6
	.quad gate7
	.quad gate8
	.quad gate9
	.quad gate10
	.quad gate11
	.quad gate12
	.quad gate13
	.quad gate14
	.quad gate15
	.quad gate16
	.quad gate17
	.quad gate18
	.quad gate19
	.quad gate20
	.quad gate21
	.quad gate22
	.quad gate23
	.quad gate24
	.quad gate25
	.quad gate26
	.quad gate27
	.quad gate28
	.quad gate29
	.quad gate30
	.quad gate31
	.quad gate32
	.quad gate33
	.quad gate34
	.quad gate35
	.quad gate36
	.quad gate37
	.quad gate38
	.quad gate39
	.quad gate40
	.quad gate41
	.quad gate42
	.quad gate43
	.quad gate44
	.quad gate45
	.quad gate46
	.quad gate47
	.quad gate48
	.quad gate49
	.quad gate50
	.quad gate51
	.quad gate52
	.quad gate53
	.quad gate54
	.quad gate55
	.quad gate56
	.quad gate57
	.quad gate58
	.quad gate59
	.quad gate60
	.quad gate61
	.quad gate62
	.quad gate63
	.quad gate64
	.quad gate65
	.quad gate66
	.quad gate67
	.quad gate68
	.quad gate69
	.quad gate70
	.quad gate71
	.quad gate72
	.quad gate73
	.quad gate74
	.quad gate75
	.quad gate76
	.quad gate77
	.quad gate78
	.quad gate79
	.quad gate80
	.quad gate81
	.quad gate82
	.quad gate83
	.quad gate84
	.quad gate85
	.quad gate86
	.quad gate87
	.quad gate88
	.quad gate89
	.quad gate90
	.quad gate91
	.quad gate92
	.quad gate93
	.quad gate94
	.quad gate95
	.quad gate96
	.quad gate97
	.quad gate98
	.quad gate99
	.quad gate100
	.quad gate101
	.quad gate102
	.quad gate103
	.quad gate104
	.quad gate105
	.quad gate106
	.quad gate107
	.quad gate108
	.quad gate109
	.quad gate110
	.quad gate111
	.quad gate112
	.quad gate113
	.quad gate114
	.quad gate115
	.quad gate116
	.quad gate117
	.quad gate118
	.quad gate119
	.quad gate120
	.quad gate121
	.quad gate122
	.quad gate123
	.quad gate124
	.quad gate125
	.quad gate126
	.quad gate127
	.quad gate128
	.quad gate129
	.quad gate130
	.quad gate131
	.quad gate132
	.quad gate133
	.quad gate134
	.quad gate135
	.quad gate136
	.quad gate137
	.quad gate138
	.quad gate139
	.quad gate140
	.quad gate141
	.quad gate142
	.quad gate143
	.quad gate144
	.quad gate145
	.quad gate146
	.quad gate147
	.quad gate148
	.quad gate149
	.quad gate150
	.quad gate151
	.quad gate152
	.quad gate153
	.quad gate154
	.quad gate155
	.quad gate156
	.quad gate157
	.quad gate158
	.quad gate159
	.quad gate160
	.quad gate161
	.quad gate162
	.quad gate163
	.quad gate164
	.quad gate165
	.quad gate166
	.quad gate167
	.quad gate168
	.quad gate169
	.quad gate170
	.quad gate171
	.quad gate172
	.quad gate173
	.quad gate174
	.quad gate175
	.quad gate176
	.quad gate177
	.quad gate178
	.quad gate179
	.quad gate180
	.quad gate181
	.quad gate182
	.quad gate183
	.quad gate184
	.quad gate185
	.quad gate186
	.quad gate187
	.quad gate188
	.quad gate189
	.quad gate190
	.quad gate191
	.quad gate192
	.quad gate193
	.quad gate194
	.quad gate195
	.quad gate196
	.quad gate197
	.quad gate198
	.quad gate199
	.quad gate200
	.quad gate201
	.quad gate202
	.quad gate203
	.quad gate204
	.quad gate205
	.quad gate206
	.quad gate207
	.quad gate208
	.quad gate209
	.quad gate210
	.quad gate211
	.quad gate212
	.quad gate213
	.quad gate214
	.quad gate215
	.quad gate216
	.quad gate217
	.quad gate218
	.quad gate219
	.quad gate220
	.quad gate221
	.quad gate222
	.quad gate223
	.quad gate224
	.quad gate225
	.quad gate226
	.quad gate227
	.quad gate228
	.quad gate229
	.quad gate230
	.quad gate231
	.quad gate232
	.quad gate233
	.quad gate234
	.quad gate235
	.quad gate236
	.quad gate237
	.quad gate238
	.quad gate239
	.quad gate240
	.quad gate241
	.quad gate242
	.quad gate243
	.quad gate244
	.quad gate245
	.quad gate246
	.quad gate247
	.quad gate248
	.quad gate249
	.quad gate250
	.quad gate251
	.quad gate252
	.quad gate253
	.quad gate254
	.quad gate255
