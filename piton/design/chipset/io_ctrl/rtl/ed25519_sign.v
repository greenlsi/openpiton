module ed25519_sign_S_core_TOP (
	input			ICLK,
	input			IRST,
	input			IEN,
	output			OREADY,
	output			ODONE,
	input	[250:0]	IHASHD_KEY,
	input	[511:0]	IHASHD_RAM,
	input	[511:0]	IHASHD_SM,
	output	[252:0]	OSIGN
);

ed25519_sign_S_core uut (
	.iClk			(ICLK),
	.iRst			(IRST),
	.iEn			(IEN),
	.oReady			(OREADY),
	.oDone			(ODONE),
	.iHashd_key		(IHASHD_KEY),
	.iHashd_ram		(IHASHD_RAM),
	.iHashd_sm		(IHASHD_SM),
	.oSign			(OSIGN)
);
 
endmodule
/*
Edited from the original ed25519_sign_core
the reason is that we trim the SHA512 and the scalar multipliers
This core only computes S from the R,S pair in the sign
for calculating R, take r and use the base-point multiplier
*/

module ed25519_sign_S_core (
	input			iClk,
	input			iRst,
	
	/* Control signals */
	input			iEn,
	output			oReady,
	output			oDone,
	
	/* Secret key hashed S = H(k) */
	input	[250:0]	iHashd_key,
	/* H(R, A, M) */
	input	[511:0]	iHashd_ram,
	/* H(S, M). */
	input	[511:0]	iHashd_sm,
	
	/* A signature is a pair, but we only output 1 part (R,S) */
	output	[252:0]	oSign
);

/*****************************************************************************
 *                            Combinational Logic                            *
 *****************************************************************************/

 reg	[2:0]	State;
 wire	[2:0]	nextState;
 
 wire			State0, State1, State2, State3,
				State4, State5, State6, State7;
 
 reg			FSM_mult_Start;
 wire			FSM_mult_Start_w;
 
 //Multipliers
 wire	[255:0]	mult_iA;
 wire	[255:0]	mult_iB;
 wire			mult_oDone;
 wire	[511:0]	mult_oX;
 
 //barrett_reduce
 wire			red_iEn;
 wire	[511:0]	red_iIn;
 wire			red_oDone;
 wire	[252:0]	red_oResult;
 wire			red_mult_Start;
 wire	[255:0]	red_mult_A;
 wire	[255:0]	red_mult_B;
 
 //registers
 reg	[511:0]	HRAM_A;
 reg	[255:0]	R;
 reg	[255:0]	HRAM;
 
 //Inputs & Outputs
 wire	[255:0]	Pre_HashKey;
 wire	[255:0]	HashKey;
 wire	[252:0]	Pre_Sign;
 
 //Optimize
 wire			State246;
 wire			State1246;
 wire			State56;
 wire			State0_En;
 wire			State1_redDone;
 wire			State1_redDoneN;
 wire			State2_redDone;
 wire			State3_mulDone;
 wire			State3_mulDoneN;
 wire			State4_redDone;
 wire			State6_redDone;
 
/*****************************************************************************
 *                            Combinational Logic                            *
 *****************************************************************************/

 assign State0  = ~State[2] & ~State[1] & ~State[0];
 assign State1  = ~State[2] & ~State[1] &  State[0];
 assign State2  = ~State[2] &  State[1] & ~State[0];
 assign State3  = ~State[2] &  State[1] &  State[0];
 assign State4  =  State[2] & ~State[1] & ~State[0];
 assign State5  =  State[2] & ~State[1] &  State[0];
 assign State6  =  State[2] &  State[1] & ~State[0];
 assign State7  =  State[2] &  State[1] &  State[0];
 
 //Optimize
 assign State246 = State2 | State4 | State6;
 assign State1246 = State1 | State246;
 assign State56 = State5 | State6;
 assign State0_En = State0 & iEn;
 assign State1_redDone = State1 & red_oDone;
 assign State1_redDoneN = State1 & ~red_oDone;
 assign State2_redDone = State2 & red_oDone;
 assign State3_mulDone = State3 & mult_oDone;
 assign State3_mulDoneN = State3 & ~mult_oDone;
 assign State4_redDone = State4 & red_oDone;
 assign State6_redDone = State6 & red_oDone;
 
 //Multipliers
 assign mult_iA = (State1246) ? red_mult_A : HRAM;
 assign mult_iB = (State1246) ? red_mult_B : HashKey;
 
 //assign Pre_HashKey = {iHashd_key[511:507], 3'b0, iHashd_key[503:264],2'b01,iHashd_key[261:256]};
 assign Pre_HashKey = {iHashd_key[250:246], 3'b0, iHashd_key[245:6],2'b01,iHashd_key[5:0]};
 assign HashKey = {Pre_HashKey[7:0]    , Pre_HashKey[15:8]   , Pre_HashKey[23:16]  , Pre_HashKey[31:24]  ,
				   Pre_HashKey[39:32]  , Pre_HashKey[47:40]  , Pre_HashKey[55:48]  , Pre_HashKey[63:56]  ,
				   Pre_HashKey[71:64]  , Pre_HashKey[79:72]  , Pre_HashKey[87:80]  , Pre_HashKey[95:88]  ,
				   Pre_HashKey[103:96] , Pre_HashKey[111:104], Pre_HashKey[119:112], Pre_HashKey[127:120],
				   Pre_HashKey[135:128], Pre_HashKey[143:136], Pre_HashKey[151:144], Pre_HashKey[159:152],
				   Pre_HashKey[167:160], Pre_HashKey[175:168], Pre_HashKey[183:176], Pre_HashKey[191:184],
				   Pre_HashKey[199:192], Pre_HashKey[207:200], Pre_HashKey[215:208], Pre_HashKey[223:216],
				   Pre_HashKey[231:224], Pre_HashKey[239:232], Pre_HashKey[247:240], Pre_HashKey[255:248]};
 
 //barrett_reduce controls
 assign red_iEn = State1246;
 assign red_iIn = (State1) ? iHashd_sm :
				  (State2) ? iHashd_ram :
				  (State4) ? HRAM_A : HRAM;
 
 //Outputs
 assign oReady = State0;
 assign oDone = State7;
 
 assign Pre_Sign = HRAM[252:0];
 assign oSign = {Pre_Sign[7:0]    , Pre_Sign[15:8]   , Pre_Sign[23:16]  , Pre_Sign[31:24]  ,
				 Pre_Sign[39:32]  , Pre_Sign[47:40]  , Pre_Sign[55:48]  , Pre_Sign[63:56]  ,
				 Pre_Sign[71:64]  , Pre_Sign[79:72]  , Pre_Sign[87:80]  , Pre_Sign[95:88]  ,
				 Pre_Sign[103:96] , Pre_Sign[111:104], Pre_Sign[119:112], Pre_Sign[127:120],
				 Pre_Sign[135:128], Pre_Sign[143:136], Pre_Sign[151:144], Pre_Sign[159:152],
				 Pre_Sign[167:160], Pre_Sign[175:168], Pre_Sign[183:176], Pre_Sign[191:184],
				 Pre_Sign[199:192], Pre_Sign[207:200], Pre_Sign[215:208], Pre_Sign[223:216],
				 Pre_Sign[231:224], Pre_Sign[239:232], Pre_Sign[247:240], Pre_Sign[252:248]};

/*****************************************************************************
 *                             Sequential Logic                              *
 *****************************************************************************/
 
 always@(posedge iClk) begin
	if(State3_mulDone)	HRAM_A <= mult_oX;
	else				HRAM_A <= HRAM_A;
 end

 always@(posedge iClk) begin
	if(State1_redDone)	R <= red_oResult;
	else				R <= R;
 end

 always@(posedge iClk) begin 
	if(State5)	HRAM <= R + HRAM;
	else if((red_oDone & State246))
				HRAM <= red_oResult;
	else		HRAM <= HRAM;
 end

/*****************************************************************************
 *                              Internal Modules                             *
 *****************************************************************************/
 
 mult_512_byAdder mult (
	.iClk		(iClk),
	.iRst		(iRst),
	.iStart		(FSM_mult_Start | red_mult_Start),
	.iA			(mult_iA),
	.iB			(mult_iB),
	.oDone		(mult_oDone),
	.oX			(mult_oX)
 );

 barrett_reduce red (
	.iClk		(iClk),
	.iRst		(iRst),
	.iIn		(red_iIn),
	.iEn		(red_iEn),
	.oDone		(red_oDone),
	.oResult	(red_oResult),
	.oMulStart	(red_mult_Start),
	.oMul_D0	(red_mult_A),
	.oMul_D1	(red_mult_B),
	.iMulDone	(mult_oDone),
	.iMul_Q		(mult_oX)
 );

/*****************************************************************************
 *                           Finite State Machine                            *
 *****************************************************************************/
/*
 localparam STATE_IDLE			= 4'd0,
			STATE_REDUCE_R		= 4'd1,
			STATE_REDUCE_HRAM	= 4'd2,
			STATE_MULT_HRAM_A	= 4'd3,
			STATE_REDUCE_HRAM_A	= 4'd4,
			STATE_ADD_R_HRAMA	= 4'd5,
			STATE_REDUCE_FINAL	= 4'd6,
			STATE_OUTPUT		= 4'd7;
*/
/*
 always@(posedge iClk) begin
	if(iRst) begin
		State <= 4'd0;
		FSM_mult_Start <= 1'b0;
	end
	else begin
		case(State)
			4'd0: begin
				FSM_mult_Start <= 1'b0;
				if(iEn)	State <= 4'd1;
				else	State <= State;
			end
			4'd1: begin
				FSM_mult_Start <= 1'b0;
				if(red_oDone)	State <= 4'd2;
				else			State <= State;
			end
			4'd2: begin
				if(red_oDone) begin
					State <= 4'd3;
					FSM_mult_Start <= 1'b1; end
				else begin
					State <= State;
					FSM_mult_Start <= 1'b0; end
			end
			4'd3: begin
				if(mult_oDone) begin
					State <= 4'd4;
					FSM_mult_Start <= 1'b0; end
				else begin
					State <= State;
					FSM_mult_Start <= 1'b0; end
			end
			4'd4: begin
				FSM_mult_Start <= 1'b0;
				if(red_oDone)	State <= 4'd5;
				else			State <= State;
			end
			4'd5: begin
				State <= 4'd6;
				FSM_mult_Start <= 1'b0;
			end
			4'd6: begin
				FSM_mult_Start <= 1'b0;
				if(red_oDone)	State <= 4'd7;
				else			State <= State;
			end
			4'd7: begin
				State <= 4'd0;
				FSM_mult_Start <= 1'b0;
			end
			default: begin
				State <= 4'd0;
				FSM_mult_Start <= 1'b0;
			end
		endcase
	end
 end
*/

/*****************************************************************************
 *                           Finite State Machine                            *
 *****************************************************************************/
/*
 localparam STATE_IDLE			= 4'd0,
			STATE_REDUCE_R		= 4'd1,
			STATE_REDUCE_HRAM	= 4'd2,
			STATE_MULT_HRAM_A	= 4'd3,
			STATE_REDUCE_HRAM_A	= 4'd4,
			STATE_ADD_R_HRAMA	= 4'd5,
			STATE_REDUCE_FINAL	= 4'd6,
			STATE_OUTPUT		= 4'd7;
*/
/*
 always@(posedge iClk) begin
	if(iRst)	State <= 4'd0;
	else begin
		case(State)
			4'd0: begin
				if(iEn)	State <= 4'd1;
				else	State <= State;
			end
			4'd1: begin
				if(red_oDone)	State <= 4'd2;
				else			State <= State;
			end
			4'd2: begin
				if(red_oDone)	State <= 4'd3;
				else 			State <= State;
			end
			4'd3: begin
				if(mult_oDone) 	State <= 4'd4;
				else 			State <= State;
			end
			4'd4: begin
				if(red_oDone)	State <= 4'd5;
				else			State <= State;
			end
			4'd5: begin
				State <= 4'd6;
			end
			4'd6: begin
				if(red_oDone)	State <= 4'd7;
				else			State <= State;
			end
			4'd7: begin
				State <= 4'd0;
			end
			default: begin
				State <= State;
			end
		endcase
	end
 end
*/
 assign nextState[0] = (State0_En | State1_redDoneN) |
					   (State2_redDone | State3_mulDoneN) |
					   (State4_redDone | State6_redDone);
 assign nextState[1] = (State1_redDone | State3_mulDoneN) | (State2 | State56);
 assign nextState[2] = State3_mulDone | State4 | State56;
 always@(posedge iClk) begin
	if(iRst)	State <= 3'b0;
	else		State <= nextState;
 end

/*
 always@(posedge iClk) begin
	if(iRst)	FSM_mult_Start <= 1'b0;
	else begin
		case(State)
			4'd0: begin
				FSM_mult_Start <= 1'b0;
			end
			4'd1: begin
				FSM_mult_Start <= 1'b0;
			end
			4'd2: begin
				if(red_oDone)	FSM_mult_Start <= 1'b1;
				else 			FSM_mult_Start <= 1'b0;
			end
			4'd3: begin
				if(mult_oDone)	FSM_mult_Start <= 1'b0;
				else			FSM_mult_Start <= 1'b0;
			end
			4'd4: begin
				FSM_mult_Start <= 1'b0;
			end
			4'd5: begin
				FSM_mult_Start <= 1'b0;
			end
			4'd6: begin
				FSM_mult_Start <= 1'b0;
			end
			4'd7: begin
				FSM_mult_Start <= 1'b0;
			end
			default: begin
				FSM_mult_Start <= FSM_mult_Start;
			end
		endcase
	end
 end
*/
 assign FSM_mult_Start_w = State2_redDone;
 always@(posedge iClk) begin
	if(iRst)	FSM_mult_Start <= 1'b0;
	else		FSM_mult_Start <= FSM_mult_Start_w;
 end

endmodule
module mult_512_byAdder (
	input				iClk,
	input				iRst,
	input				iStart,
	input		[255:0]	iA,
	input		[255:0]	iB,
	output	reg			oDone,
	output	reg	[511:0]	oX
);

/*****************************************************************************
 *                 Internal Wires and Registers Declarations                 *
 *****************************************************************************/
 
 reg	[255:0]	A_in;
 wire	[255:0]	A_in_w;
 reg	[511:0]	B_in;
 wire	[511:0]	B_in_w;
 
 reg	[8:0]	counter;
 wire	[8:0]	counter_w;
 
 reg			State;
 wire			nextState;
 
 wire	[511:0]	X_w;
 
 wire			StateN_iStart;
 wire			StateN_iStart_n;
 wire			State_counter8N;
 wire			State_counter8;

/*****************************************************************************
 *                            Combinational Logic                            *
 *****************************************************************************/
 
 assign StateN_iStart = ~State & iStart;
 assign StateN_iStart_n = ~StateN_iStart;
 assign State_counter8N = State & ~counter[8];
 assign State_counter8 = State & counter[8];
 
/*****************************************************************************
 *                             Sequential Logic                              *
 *****************************************************************************/
 
 /*
 always@(posedge iClk) begin
	if(iStart)		A_in <= iA;
	else if(State)	A_in <= {A_in[0], A_in[255:1]};
	else			A_in <= A_in;
 end
 */
 assign A_in_w = (iStart) ? iA :
				 (State) ? {A_in[0], A_in[255:1]} : A_in;
 always@(posedge iClk) begin
	A_in <= A_in_w;
 end
 
 /*
 always@(posedge iClk) begin
	if(iStart)		B_in <= {256'b0,iB};
	else if(State)	B_in <= {B_in[510:0], 1'b0};
	else			B_in <= B_in;
 end
 */
 assign B_in_w[511:256] = {(256){~iStart}} & ( (State) ? B_in[510:255] : B_in[511:256] );
 assign B_in_w[255:1]   = (iStart) ? iB[255:1] : ( (State) ? B_in[254:0] : B_in[255:1] );
 assign B_in_w[0]       = (iStart) ? iB[0]     : ( ~State & B_in[0] );
 always@(posedge iClk) begin
	B_in <= B_in_w;
 end
 
/*****************************************************************************
 *                           Finite State Machine                            *
 *****************************************************************************/
 /*
 always@(posedge iClk) begin
	if(iRst) begin
		State <= 1'b0;
		counter <= 9'b0;
		oDone <= 1'b0;
		oX <= 512'b0; end
	else begin
		case(State)
			1'b0: begin
				oDone <= 1'b0;
				if(iStart) begin
					State <= 1'b1;
					counter <= 9'b0;
					oX <= 512'b0; end
				else begin
					State <= 1'b0;
					counter <= counter;
					oX <= oX; end
			end
			1'b1: begin
				if(counter[8]) begin
					State <= 1'b0;
					counter <= 9'b0;
					oDone <= 1'b1;
					oX <= oX; end
				else begin
					State <= 1'b1;
					counter <= counter + 1'b1;
					oDone <= 1'b0;
					if(A_in[0])	oX <= oX + B_in;
					else		oX <= oX; end
			end
		endcase
	end
 end
 */
 
/*****************************************************************************
 *                           Finite State Machine                            *
 *****************************************************************************/
 /*
 always@(posedge iClk) begin
	if(iRst)	State <= 1'b0;
	else begin
		case(State)
			1'b0: begin
				if(iStart)		State <= 1'b1;
				else			State <= 1'b0;
			end
			1'b1: begin
				if(counter[8])	State <= 1'b0;
				else 			State <= 1'b1;
			end
		endcase
	end
 end
 */
 assign nextState = StateN_iStart | State_counter8N;
 always@(posedge iClk) begin
	if(iRst)	State <= 1'b0;
	else		State <= nextState;
 end
 
 /*
 always@(posedge iClk) begin
	if(iRst)	counter <= 9'b0;
	else begin
		case(State)
			1'b0: begin
				if(iStart)		counter <= 9'b0;
				else			counter <= counter;
			end
			1'b1: begin
				if(counter[8])	counter <= 9'b0;
				else			counter <= counter + 1'b1;
			end
		endcase
	end
 end
 */
 assign counter_w = {(9){StateN_iStart_n}} & {(9){~State_counter8}} &
					( (State_counter8N) ? (counter + 1'b1) : counter );
 always@(posedge iClk) begin
	if(iRst)	counter <= 9'b0;
	else		counter <= counter_w;
 end
 
 /*
 always@(posedge iClk) begin
	if(iRst)	oDone <= 1'b0;
	else if(State & counter[8])
				oDone <= 1'b1;
	else		oDone <= 1'b0;
 end
 */
 always@(posedge iClk) begin
	if(iRst)	oDone <= 1'b0;
	else		oDone <= State_counter8;
 end
 
 /*
 always@(posedge iClk) begin
	if(iRst)	oX <= 512'b0;
	else begin
		case(State)
			1'b0: begin
				if(iStart)	oX <= 512'b0;
				else		oX <= oX;
			end
			1'b1: begin
				if(counter[8])		oX <= oX;
				else if(A_in[0])	oX <= oX + B_in;
				else				oX <= oX;
			end
		endcase
	end
 end
 */
 assign X_w = {(512){StateN_iStart_n}} &
			  ( (State_counter8N & A_in[0]) ? (oX + B_in) : oX );
 always@(posedge iClk) begin
	if(iRst)	oX <= 512'b0;
	else		oX <= X_w;
 end
 
endmodule
/* Reduce a 512 bit number mod 2**252
*                               + 27742317777372353535851937790883648493 */

module barrett_reduce (
    input				iClk,
    input				iRst,
	
    /* Control signals */
    input				iEn,
	input		[511:0]	iIn,
    output				oDone,
	output		[252:0]	oResult,
	
    /* To the multipliers */
	output	reg			oMulStart,
    output		[255:0]	oMul_D0,
    output		[255:0]	oMul_D1,
	input				iMulDone,
	input		[511:0]	iMul_Q
);

/*****************************************************************************
 *                           Parameter Declarations                          *
 *****************************************************************************/

/* For barrett reduction */
/* 2**252 + 27742317777372353535851937790883648493 */
localparam m = 253'h1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
/* 4**256 / m */
localparam mu = 260'hfffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c131b;

/*****************************************************************************
 *                 Internal Wires and Registers Declarations                 *
 *****************************************************************************/

 reg	[3:0]	State;
 wire	[3:0]	nextState;
 
 wire			State0, State1, State2, State3,
				State4, State5, State6, State7,
				State8, State9, State10;
 
 wire			MulStart_w;

 reg			compare_flag_reg;
 reg			compare_flag_new;

 wire	[253:0]	sub_in_0;
 wire	[253:0]	sub_in_1;

 reg	[515:0]	layer2;
 reg	[253:0]	sub_out;
 
 reg	[511:0]	data_out_bram_1;
 reg	[511:0]	data_out_bram_2;
 reg	[511:0]	data_out_bram_3;
 reg	[252:0]	data_out_bram_c1;
 reg	[252:0]	data_out_bram_c2;
 
 wire			State0_En;
 wire			State1_MulDone;
 wire			State2_MulDone;
 wire			State3_MulDone;
 wire			State3_MulDoneN;
 wire			State5_or6;

/*****************************************************************************
 *                            Combinational Logic                            *
 *****************************************************************************/
 
 assign State0  = (~State[3] & ~State[2]) & (~State[1] & ~State[0]);
 assign State1  = (~State[3] & ~State[2]) & (~State[1] &  State[0]);
 assign State2  = (~State[3] & ~State[2]) & ( State[1] & ~State[0]);
 assign State3  = (~State[3] & ~State[2]) & ( State[1] &  State[0]);
 assign State4  = (~State[3] &  State[2]) & (~State[1] & ~State[0]);
 assign State5  = (~State[3] &  State[2]) & (~State[1] &  State[0]);
 assign State6  = (~State[3] &  State[2]) & ( State[1] & ~State[0]);
 assign State7  = (~State[3] &  State[2]) & ( State[1] &  State[0]);
 assign State8  = ( State[3] & ~State[2]) & (~State[1] & ~State[0]);
 assign State9  = ( State[3] & ~State[2]) & (~State[1] &  State[0]);
 assign State10 = ( State[3] & ~State[2]) & ( State[1] & ~State[0]);
 
assign oMul_D0 = (State1|State3) ? iIn[255:0] :
				 (State2|State4) ? iIn[511:256] : layer2[511:256];

assign oMul_D1 = (State1|State2) ? mu[255:0] :
				 (State3|State4) ? {252'b0, mu[259:256]} : {3'b0, m};

assign sub_in_0 = (State7) ? iIn[253:0] : sub_out;
assign sub_in_1 = (State7) ? iMul_Q[253:0] : {1'b0, m};
				  
 //Outputs controls
 assign oDone = State10;
 
 //Optimize
 assign State0_En = State0 & iEn;
 assign State1_MulDone = State1 & iMulDone;
 assign State2_MulDone = State2 & iMulDone;
 assign State3_MulDone = State3 & iMulDone;
 assign State3_MulDoneN = State3 & ~iMulDone;
 assign State5_or6 = State5 | State6;

/*****************************************************************************
 *                             Sequential Logic                              *
 *****************************************************************************/

 always@(posedge iClk) begin
	if(State1_MulDone)	data_out_bram_1 <= iMul_Q;
	else				data_out_bram_1 <= data_out_bram_1;
 end

 always@(posedge iClk) begin
	if(State2_MulDone)	data_out_bram_2 <= iMul_Q;
	else				data_out_bram_2 <= data_out_bram_2;
 end

 always@(posedge iClk) begin
	if(State3_MulDone)	data_out_bram_3 <= iMul_Q;
	else				data_out_bram_3 <= data_out_bram_3;
 end

 always@(posedge iClk) begin
	if(State8)	data_out_bram_c1 <= sub_out[252:0];
	else		data_out_bram_c1 <= data_out_bram_c1;
 end

 always@(posedge iClk) begin
	if(State9)	data_out_bram_c2 <= sub_out[252:0];
	else		data_out_bram_c2 <= data_out_bram_c2;
 end
 
 always@(posedge iClk) begin
	layer2	<= (data_out_bram_1[511:256] + data_out_bram_2) + (data_out_bram_3 + {iMul_Q[259:0], 256'b0});
	sub_out	<= sub_in_0 - sub_in_1;
 end

 //Outputs result
 always@(posedge iClk) begin
	if(State9)	compare_flag_reg <= (data_out_bram_c1 > m);
	else		compare_flag_reg <= compare_flag_reg;
 end
 assign oResult = (compare_flag_reg) ? data_out_bram_c2 : data_out_bram_c1;

/*****************************************************************************
 *                           Finite State Machine                            *
 *****************************************************************************/
/*
 localparam STATE_IDLE			= 4'd0,
		    STATE_LONG_MULT_1	= 4'd1,
		    STATE_LONG_MULT_2	= 4'd2,
		    STATE_LONG_MULT_3	= 4'd3,
		    STATE_LONG_MULT_4	= 4'd4,
		    STATE_ADD			= 4'd5,
		    STATE_SHORT_MULT	= 4'd6,
		    STATE_SUB			= 4'd7,
		    STATE_SAVE_SUB		= 4'd8,
		    STATE_SAVE_COMPARE	= 4'd9,
		    STATE_OUTPUT		= 4'd10,
		    STATE_DONE			= 4'd11;
*/
/*
 always@(posedge iClk) begin
	if(iRst) begin
		State <= 4'd0;
		oMulStart <= 1'b0;
	end
	else begin
		case(State)
			4'd0: begin
				if(iEn) begin
					State		<= 4'd1;
					oMulStart	<= 1'b1; end
				else begin
					State		<= State;
					oMulStart	<= 1'b0; end
			end
			4'd1: begin
				if(iMulDone) begin
					State		<= 4'd2;
					oMulStart	<= 1'b1; end
				else begin
					State		<= State;
					oMulStart	<= 1'b0; end
			end
			4'd2: begin
				if(iMulDone) begin
					State		<= 4'd3;
					oMulStart	<= 1'b1; end
				else begin
					State		<= State;
					oMulStart	<= 1'b0; end
			end
			4'd3: begin
				if(iMulDone) begin
					State		<= 4'd4;
					oMulStart	<= 1'b1; end
				else begin
					State		<= State;
					oMulStart	<= 1'b0; end
			end
			4'd4: begin
				oMulStart				<= 1'b0;
				if(iMulDone)	State	<= 4'd5;
				else			State	<= State;
			end
			4'd5: begin
				State		<= 4'd6;
				oMulStart	<= 1'b1;
			end
			4'd6: begin
				oMulStart				<= 1'b0;
				if(iMulDone)	State	<= 4'd7;
				else			State	<= State;
			end
			4'd7: begin
				State		<= 4'd8;
				oMulStart	<= 1'b0;
			end
			4'd8: begin
				State		<= 4'd9;
				oMulStart	<= 1'b0;
			end
			4'd9: begin
				State		<= 4'd10;
				oMulStart	<= 1'b0;
			end
			4'd10: begin
				State		<= 4'd0;
				oMulStart	<= 1'b0;
			end
			default: begin
				State		<= State;
				oMulStart	<= oMulStart;
			end
		endcase
	end
 end
*/

/*****************************************************************************
 *                           Finite State Machine                            *
 *****************************************************************************/
/*
 localparam STATE_IDLE			= 4'd0,
		    STATE_LONG_MULT_1	= 4'd1,
		    STATE_LONG_MULT_2	= 4'd2,
		    STATE_LONG_MULT_3	= 4'd3,
		    STATE_LONG_MULT_4	= 4'd4,
		    STATE_ADD			= 4'd5,
		    STATE_SHORT_MULT	= 4'd6,
		    STATE_SUB			= 4'd7,
		    STATE_SAVE_SUB		= 4'd8,
		    STATE_SAVE_COMPARE	= 4'd9,
		    STATE_OUTPUT		= 4'd10,
		    STATE_DONE			= 4'd11;
*/
/*
 always@(posedge iClk) begin
	if(iRst)	State <= 4'd0;
	else begin
		case(State)
			4'd0: begin
				if(iEn)	State <= 4'd1;
				else		State <= State;
			end
			4'd1: begin
				if(iMulDone)	State <= 4'd2;
				else			State <= State;
			end
			4'd2: begin
				if(iMulDone)	State <= 4'd3;
				else			State <= State;
			end
			4'd3: begin
				if(iMulDone)	State <= 4'd4;
				else			State <= State;
			end
			4'd4: begin
				if(iMulDone)	State <= 4'd5;
				else			State <= State;
			end
			4'd5: begin
				State <= 4'd6;
			end
			4'd6: begin
				if(iMulDone)	State <= 4'd7;
				else			State <= State;
			end
			4'd7: begin
				State <= 4'd8;
			end
			4'd8: begin
				State <= 4'd9;
			end
			4'd9: begin
				State <= 4'd10;
			end
			4'd10: begin
				State <= 4'd0;
			end
			default: begin
				State <= State;
			end
		endcase
	end
 end
*/
 assign nextState[0] = ( (State0_En | State2_MulDone) | (State3_MulDoneN | State8) ) |
					   ( (State1 & ~iMulDone) | (State4 & iMulDone) | (State6 & iMulDone) );
 assign nextState[1] = ( State1_MulDone  | State2 ) |
					   ( State3_MulDoneN | State9 | State5_or6 );
 assign nextState[2] = State3_MulDone | State4 | State5_or6;
 assign nextState[3] = State7 | State8 | State9;
 always@(posedge iClk) begin
	if(iRst)	State <= 4'b0;
	else		State <= nextState;
 end

/*
 always@(posedge iClk) begin
	if(iRst)	oMulStart <= 1'b0;
	else begin
		case(State)
			4'd0: begin
				if(iEn)	oMulStart <= 1'b1;
				else		oMulStart <= 1'b0;
			end
			4'd1: begin
				if(iMulDone)	oMulStart <= 1'b1;
				else			oMulStart <= 1'b0;
			end
			4'd2: begin
				if(iMulDone)	oMulStart <= 1'b1;
				else			oMulStart <= 1'b0;
			end
			4'd3: begin
				if(iMulDone)	oMulStart <= 1'b1;
				else			oMulStart <= 1'b0;
			end
			4'd4: begin
				oMulStart <= 1'b0;
			end
			4'd5: begin
				oMulStart <= 1'b1;
			end
			4'd6: begin
				oMulStart <= 1'b0;
			end
			4'd7: begin
				oMulStart <= 1'b0;
			end
			4'd8: begin
				oMulStart <= 1'b0;
			end
			4'd9: begin
				oMulStart <= 1'b0;
			end
			4'd10: begin
				oMulStart <= 1'b0;
			end
			default: begin
				oMulStart <= oMulStart;
			end
		endcase
	end
end
*/
 assign MulStart_w = (State0_En | State1_MulDone) |
					 (State2_MulDone | State3_MulDone | State5);
 always@(posedge iClk) begin
	if(iRst)	oMulStart <= 1'b0;
	else		oMulStart <= MulStart_w;
 end

endmodule
module ed25519_sign_S_core_TOP_wrapper (
	input			clk,
	input			rst,
	input			core_ena,
	output			core_ready,
	output			core_comp_done,
	input	[511:0]	hashd_key,
	input	[511:0]	hashd_ram,
	input	[511:0]	hashd_sm,
	output	[255:0]	core_S
);

wire [252:0] sign;

ed25519_sign_S_core_TOP U1_TOP (
	.ICLK			(clk),
	.IRST			(rst),
	.IEN			(core_ena),
	.OREADY			(core_ready),
	.ODONE			(core_comp_done),
	.IHASHD_KEY		({hashd_key[511:507], hashd_key[503:264], hashd_key[261:256]}),
	.IHASHD_RAM		(hashd_ram),
	.IHASHD_SM		(hashd_sm),
	.OSIGN			(sign)
);
assign core_S = {sign[252:5], 3'b0, sign[4:0]};
 
endmodule