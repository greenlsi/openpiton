`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 03/06/2025 10:38:32 AM
// Design Name: 
// Module Name: ed25519_axi_wrapper
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module ed25519_axi_wrapper #(
    parameter C_S_AXI_DATA_WIDTH = 64,
    parameter C_S_AXI_ADDR_WIDTH = 64
)(
    // Global Clock Signal
    input  wire        S_AXI_ACLK,
    // Global Reset Signal. This Signal is Active LOW
    input  wire        S_AXI_ARESETN,

    // AXI Write Address Channel

    // Write address (issued by master, acceped by Slave)
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] S_AXI_AWADDR,
    // Write channel Protection type. This signal indicates the
    // privilege and security level of the transaction, and whether
    // the transaction is a data access or an instruction access.
    input  wire [2 : 0] S_AXI_AWPROT,
    // Write address valid. This signal indicates that the master signaling
    // valid write address and control information.
    input  wire        S_AXI_AWVALID,
    // Write address ready. This signal indicates that the slave is ready
    // to accept an address and associated control signals.
    output wire        S_AXI_AWREADY,

    // AXI Write Data Channel

    // Write data (issued by master, acceped by Slave)
    input  wire [C_S_AXI_DATA_WIDTH-1:0] S_AXI_WDATA,
    // Write strobes. This signal indicates which byte lanes hold
    // valid data. There is one write strobe bit for each eight
    // bits of the write data bus.
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0]  S_AXI_WSTRB,
    // Write valid. This signal indicates that valid write
    // data and strobes are available.
    input  wire        S_AXI_WVALID,
    // Write ready. This signal indicates that the slave
    // can accept the write data.
    output wire        S_AXI_WREADY,

    // AXI Write Response Channel

    // Write response. This signal indicates the status
    // of the write transaction.
    output wire [1:0]  S_AXI_BRESP,
    // Write response valid. This signal indicates that the channel
    // is signaling a valid write response.
    output wire        S_AXI_BVALID,
    // Response ready. This signal indicates that the master
    // can accept a write response.
    input  wire        S_AXI_BREADY,

    // AXI Read Address Channel

    // Read address (issued by master, acceped by Slave)
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] S_AXI_ARADDR,
    // Protection type. This signal indicates the privilege
    // and security level of the transaction, and whether the
    // transaction is a data access or an instruction access.
    input wire [2 : 0] S_AXI_ARPROT,
    // Read address valid. This signal indicates that the channel
    // is signaling valid read address and control information.
    input  wire        S_AXI_ARVALID,
    // Read address ready. This signal indicates that the slave is
    // ready to accept an address and associated control signals.
    output wire        S_AXI_ARREADY,

    // AXI Read Data Channel

    // Read data (issued by slave)
    output wire [C_S_AXI_DATA_WIDTH-1:0] S_AXI_RDATA,
    // Read response. This signal indicates the status of the
    // read transfer.
    output wire [1:0] S_AXI_RRESP,
    // Read valid. This signal indicates that the channel is
    // signaling the required read data.
    output wire        S_AXI_RVALID,
    // Read ready. This signal indicates that the master can
    // accept the read data and response information.
    input  wire        S_AXI_RREADY,

    // ED25519_mul Signals
	output wire [31:0] K_DIN,
    output reg         ENA,
    input wire  [31:0] QY_DOUT, //write to qy_reg in qy_addr  
    input wire          RDY,
    input wire  [2:0]  K_ADDR,
    input wire  [2:0]  QY_ADDR,
    input wire         QY_WREN,

	// ED25519_sign Signals
	output reg CORE_ENA,
	output wire [511:0] HASHD_KEY,
	output wire [511:0] HASHD_RAM,
	output wire [511:0] HASHD_SM,
	input wire CORE_READY,
	input wire CORE_COMP_DONE,
	input wire [255:0] CORE_S
    );


    // AXI4LITE signals. Store the values of the signals issued by AXI master
	reg [C_S_AXI_ADDR_WIDTH-1 : 0] 	axi_awaddr;
	reg  	axi_awready;
	reg  	axi_wready;
	reg [1 : 0] 	axi_bresp;
	reg  	axi_bvalid;
	reg [C_S_AXI_ADDR_WIDTH-1 : 0] 	axi_araddr;
	reg  	axi_arready;
	reg [C_S_AXI_DATA_WIDTH-1 : 0] 	axi_rdata;
	reg [1 : 0] 	axi_rresp;
	reg  	axi_rvalid;

    // Example-specific design signals
	// local parameter for addressing 32 bit / 64 bit C_S_AXI_DATA_WIDTH
	// ADDR_LSB is used for addressing 32/64 bit registers/memories
	// ADDR_LSB = 2 for 32 bits (n downto 2)
	// ADDR_LSB = 3 for 64 bits (n downto 3)
	localparam integer ADDR_LSB = (C_S_AXI_DATA_WIDTH/32) + 1;
	localparam integer OPT_MEM_ADDR_BITS = 5;
	//----------------------------------------------
	//-- Signals for user logic register space example
	//------------------------------------------------
	//-- Number of Slave Registers: 
    // 1 data in (64 bits) + 1 status (it is 32 bits but for bus coherence it is declared as 64 bits) + 8 data out (hash is 16 registers*32bits = 512 bits, so 8 registers of 64 bits are enough)

    // ed25519 registers
    reg [255:0] k_reg;
	reg [511:0] hkey_reg;
	reg [511:0] hram_reg;
	reg [511:0] hsm_reg;
    reg [255:0] qy_reg;
	reg [255:0] core_s_reg;
	reg [63:0] status3_reg;
    reg [63:0] status_reg;
	reg [31:0] k_din_reg;

	// #define ED25519_REG_DATA_K 0x00 //32B
	// #define ED25519_REG_DATA_HKEY 0x20  //64B
	// #define ED25519_REG_DATA_HRAM 0x60 //64B
	// #define ED25519_REG_DATA_HSM 0xA0 //64B
	// #define ED25519_REG_DATA_QY 0xE0 //32B
	// #define ED25519_REG_DATA_SIGN 0x100 //32B
	// #define ED25519_REG_STATUS_3 0x120 //8B
	// #define ED25519_REG_STATUS 0x128 //8B

    // axi signals
    wire	 slv_reg_rden;
	wire	 slv_reg_wren;
	reg [C_S_AXI_DATA_WIDTH-1:0]	 reg_data_out;
    integer	 byte_index;
	reg	 aw_en;

    // I/O Connections assignments

	assign S_AXI_AWREADY	= axi_awready;
	assign S_AXI_WREADY	= axi_wready;
	assign S_AXI_BRESP	= axi_bresp;
	assign S_AXI_BVALID	= axi_bvalid;
	assign S_AXI_ARREADY	= axi_arready;
	assign S_AXI_RDATA	= axi_rdata;
	assign S_AXI_RRESP	= axi_rresp;
	assign S_AXI_RVALID	= axi_rvalid;

	assign K_DIN = k_din_reg;
	assign HASHD_KEY = hkey_reg;
	assign HASHD_RAM = hram_reg;
	assign HASHD_SM = hsm_reg;

    // Implement axi_awready generation
	// axi_awready is asserted for one S_AXI_ACLK clock cycle when both
	// S_AXI_AWVALID and S_AXI_WVALID are asserted. axi_awready is
	// de-asserted when reset is low.
	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_awready <= 1'b0;
	      aw_en <= 1'b1;
	    end 
	  else
	    begin    
	      if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID && aw_en)
	        begin
	          // slave is ready to accept write address when 
	          // there is a valid write address and write data
	          // on the write address and data bus. This design 
	          // expects no outstanding transactions. 
	          axi_awready <= 1'b1;
	          aw_en <= 1'b0;
	        end
	        else if (S_AXI_BREADY && axi_bvalid)
	            begin
	              aw_en <= 1'b1;
	              axi_awready <= 1'b0;
	            end
	      else           
	        begin
	          axi_awready <= 1'b0;
	        end
	    end 
	end

    // Implement axi_awaddr latching
	// This process is used to latch the address when both 
	// S_AXI_AWVALID and S_AXI_WVALID are valid. 

	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_awaddr <= 0;
	    end 
	  else
	    begin    
	      if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID && aw_en)
	        begin
	          // Write Address latching 
	          axi_awaddr <= S_AXI_AWADDR;
	        end
	    end 
	end       

	// Implement axi_wready generation
	// axi_wready is asserted for one S_AXI_ACLK clock cycle when both
	// S_AXI_AWVALID and S_AXI_WVALID are asserted. axi_wready is 
	// de-asserted when reset is low. 

	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_wready <= 1'b0;
	    end 
	  else
	    begin    
	      if (~axi_wready && S_AXI_WVALID && S_AXI_AWVALID && aw_en )
	        begin
	          // slave is ready to accept write data when 
	          // there is a valid write address and write data
	          // on the write address and data bus. This design 
	          // expects no outstanding transactions. 
	          axi_wready <= 1'b1;
	        end
	      else
	        begin
	          axi_wready <= 1'b0;
	        end
	    end 
	end


    // Implement memory mapped register select and write logic generation
	// The write data is accepted and written to memory mapped registers when
	// axi_awready, S_AXI_WVALID, axi_wready and S_AXI_WVALID are asserted. Write strobes are used to
	// select byte enables of slave registers while writing.
	// These registers are cleared when reset (active low) is applied.
	// Slave register write enable is asserted when valid address and data are available
	// and the slave is ready to accept the write address and write data.

	//Register addresses:
			//k_reg 		0x00; 32B
			//hkey_reg = 	0x20; 64B
			//hram_reg = 	0x60; 64B
			//hsm_reg = 	0xA0; 64B
			//status3_reg = 0x120; 8B
            //status_reg 	0x128; 8B

			//Taking axi_awaddr[3+5:3] = axi_awaddr[8:3]

			//k_reg 0x00, [8:3] = 00 0000 = 6'h00
			//k_reg 0x08, [8:3] = 00 0001 = 6'h01
			//k_reg 0x10, [8:3] = 00 0010 = 6'h02
			//k_reg 0x18, [8:3] = 00 0011 = 6'h03

			//hkey_reg 0x20, [8:3] = 00 0100 = 6'h04
			//hkey_reg 0x28, [8:3] = 00 0101 = 6'h05
			//hkey_reg 0x30, [8:3] = 00 0110 = 6'h06
			//hkey_reg 0x38, [8:3] = 00 0111 = 6'h07
			//hkey_reg 0x40, [8:3] = 00 1000 = 6'h08
			//hkey_reg 0x48, [8:3] = 00 1001 = 6'h09
			//hkey_reg 0x50, [8:3] = 00 1010 = 6'h0A
			//hkey_reg 0x58, [8:3] = 00 1011 = 6'h0B

			//hram_reg 0x60, [8:3] = 00 1100 = 6'h0C
			//hram_reg 0x68, [8:3] = 00 1101 = 6'h0D
			//hram_reg 0x70, [8:3] = 00 1110 = 6'h0E
			//hram_reg 0x78, [8:3] = 00 1111 = 6'h0F
			//hram_reg 0x80, [8:3] = 01 0000 = 6'h10
			//hram_reg 0x88, [8:3] = 01 0001 = 6'h11
			//hram_reg 0x90, [8:3] = 01 0010 = 6'h12
			//hram_reg 0x98, [8:3] = 01 0011 = 6'h13

			//hsm_reg 0xA0, [8:3] = 01 0100 = 6'h14
			//hsm_reg 0xA8, [8:3] = 01 0101 = 6'h15
			//hsm_reg 0xB0, [8:3] = 01 0110 = 6'h16
			//hsm_reg 0xB8, [8:3] = 01 0111 = 6'h17
			//hsm_reg 0xC0, [8:3] = 01 1000 = 6'h18
			//hsm_reg 0xC8, [8:3] = 01 1001 = 6'h19
			//hsm_reg 0xD0, [8:3] = 01 1010 = 6'h1A
			//hsm_reg 0xD8, [8:3] = 01 1011 = 6'h1B 

			//status3_reg 0x120, [8:3] = 10 0100 = 6'h24
			//status_reg 0x128, [8:3] =  10 0101 = 6'h25

	assign slv_reg_wren = axi_wready && S_AXI_WVALID && axi_awready && S_AXI_AWVALID;

    always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      k_reg <= 0;
		  status_reg <= 0;
		  hram_reg <= 0;
		  hkey_reg <= 0;
		  hsm_reg <= 0;
		  status3_reg <= 0;
	    end         
	  else begin
	    if (slv_reg_wren)
	      begin
						
	        case ( axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] )
				6'h00:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					k_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h01:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					k_reg[64 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h02:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					k_reg[128 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h03:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					k_reg[192 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end


				6'h04:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h05:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[64 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h06:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[128 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h07:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[192 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h08:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[256 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h09:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[320 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h0A:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[384 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h0B:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hkey_reg[448 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end


				6'h0C:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h0D:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[64 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h0E:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[128 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h0F:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[192 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h10:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[256 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h11:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[320 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h12:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[384 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h13:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hram_reg[448 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
			
				
				6'h14:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h15:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[64 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h16:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[128 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h17:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[192 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h18:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[256 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h19:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[320 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h1A:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[384 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end
				6'h1B:
				for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					hsm_reg[448 + (byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
				end


				6'h24:
					if ( S_AXI_WSTRB[0] == 1 ) begin
					// Respective byte enables are asserted as per write strobes
					status3_reg[7:0] <= (S_AXI_WDATA[7:0] & ~8'b00001110) | (status3_reg[7:0] & 8'b00001110);
				end

				6'h25:
					if ( S_AXI_WSTRB[0] == 1 ) begin
					// Respective byte enables are asserted as per write strobes 
					status_reg[7:0] <= (S_AXI_WDATA[7:0] & ~8'b00000110) | (status_reg[7:0] & 8'b00000110);
				end

	          default : begin
	                      k_reg <= k_reg;
						  hkey_reg <= hkey_reg;
						  hram_reg <= hram_reg;
						  hsm_reg <= hsm_reg;
						  status3_reg <= status3_reg;
	                      status_reg <= status_reg;
	                    end
	        endcase
		end

			//Disable enable when complete
			if (QY_WREN) begin
				status_reg[0] <= 1'b0;
			end
			if(CORE_COMP_DONE) begin
				status3_reg[0] <= 1'b0;
			end

		  	// Update read-only bits of status3_reg
			if (CORE_ENA == 1'b1) begin
				status3_reg[1] <= 1'b1;
			end else if (CORE_READY == 1'b1) begin
				status3_reg[1] <= 1'b0;
			end
			status3_reg[2] <= CORE_READY;

			if(CORE_COMP_DONE == 1'b1) begin
				status3_reg[3] <= 1'b1;
			end else if (status3_reg[0] == 1'b1) begin
				status3_reg[3] <= 1'b0;
			end
			
		  	// Update read-only bits of status_reg
			if (ENA == 1'b1) begin
				status_reg[1] <= 1'b1;
			end else if (RDY == 1'b1) begin
				status_reg[1] <= 1'b0;
			end
			status_reg[2] <= RDY;
	  end
	end


    // Implement write response logic generation
	// The write response and response valid signals are asserted by the slave 
	// when axi_wready, S_AXI_WVALID, axi_wready and S_AXI_WVALID are asserted.  
	// This marks the acceptance of address and indicates the status of 
	// write transaction.

	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_bvalid  <= 0;
	      axi_bresp   <= 2'b0;
	    end 
	  else
	    begin    
	      if (axi_awready && S_AXI_AWVALID && ~axi_bvalid && axi_wready && S_AXI_WVALID)
	        begin
	          // indicates a valid write response is available
	          axi_bvalid <= 1'b1;
	          axi_bresp  <= 2'b0; // 'OKAY' response 
	        end                   // work error responses in future
	      else
	        begin
	          if (S_AXI_BREADY && axi_bvalid) 
	            //check if bready is asserted while bvalid is high) 
	            //(there is a possibility that bready is always asserted high)   
	            begin
	              axi_bvalid <= 1'b0; 
	            end  
	        end
	    end
	end

	// Implement axi_arready generation
	// axi_arready is asserted for one S_AXI_ACLK clock cycle when
	// S_AXI_ARVALID is asserted. axi_awready is 
	// de-asserted when reset (active low) is asserted. 
	// The read address is also latched when S_AXI_ARVALID is 
	// asserted. axi_araddr is reset to zero on reset assertion.

	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_arready <= 1'b0;
	      axi_araddr  <= 32'b0;
	    end 
	  else
	    begin    
	      if (~axi_arready && S_AXI_ARVALID)
	        begin
	          // indicates that the slave has acceped the valid read address
	          axi_arready <= 1'b1;
	          // Read address latching
	          axi_araddr  <= S_AXI_ARADDR;
	        end
	      else
	        begin
	          axi_arready <= 1'b0;
	        end
	    end 
	end

	// Implement axi_arvalid generation
	// axi_rvalid is asserted for one S_AXI_ACLK clock cycle when both 
	// S_AXI_ARVALID and axi_arready are asserted. The slave registers 
	// data are available on the axi_rdata bus at this instance. The 
	// assertion of axi_rvalid marks the validity of read data on the 
	// bus and axi_rresp indicates the status of read transaction.axi_rvalid 
	// is deasserted on reset (active low). axi_rresp and axi_rdata are 
	// cleared to zero on reset (active low).  
	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_rvalid <= 0;
	      axi_rresp  <= 0;
	    end 
	  else
	    begin    
	      if (axi_arready && S_AXI_ARVALID && ~axi_rvalid)
	        begin
	          // Valid read data is available at the read data bus
	          axi_rvalid <= 1'b1;
	          axi_rresp  <= 2'b0; // 'OKAY' response
	        end   
	      else if (axi_rvalid && S_AXI_RREADY)
	        begin
	          // Read data is accepted by the master
	          axi_rvalid <= 1'b0;
	        end                
	    end
	end


    // Implement memory mapped register select and read logic generation
	// Slave register read enable is asserted when valid address is available
	// and the slave is ready to accept the read address.

	// Address decoding for reading registers

		  //qy_reg 0xE0, [8:3] = 01 1100 = 6'h1C
		  //qy_reg 0xE8, [8:3] = 01 1101 = 6'h1D
		  //qy_reg 0xF0, [8:3] = 01 1110 = 6'h1E
		  //qy_reg 0xF8, [8:3] = 01 1111 = 6'h1F

		  //core_s_reg 0x100, [8:3] = 10 0000 = 6'h20
		  //core_s_reg 0x108, [8:3] = 10 0001 = 6'h21
		  //core_s_reg 0x110, [8:3] = 10 0010 = 6'h22
		  //core_s_reg 0x118, [8:3] = 10 0011 = 6'h23

		  //status3_reg 0x120, [8:3] = 10 0100 = 6'h24
		  //status_reg 0x128, [8:3] = 10 0101 = 6'h25

	assign slv_reg_rden = axi_arready & S_AXI_ARVALID & ~axi_rvalid;
	always @(*)
	begin
	      case ( axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] )
		  	6'h1C: reg_data_out <= qy_reg[63:0];
			6'h1D: reg_data_out <= qy_reg[127:64];
			6'h1E: reg_data_out <= qy_reg[191:128];
			6'h1F: reg_data_out <= qy_reg[255:192];

			6'h20: reg_data_out <= core_s_reg[63:0];
			6'h21: reg_data_out <= core_s_reg[127:64];
			6'h22: reg_data_out <= core_s_reg[191:128];
			6'h23: reg_data_out <= core_s_reg[255:192];

			6'h24: reg_data_out <= status3_reg;
			6'h25: reg_data_out <= status_reg;
	        default : reg_data_out <= 0;
	      endcase
	end


    // Output register or memory read data
	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      axi_rdata  <= 0;
	    end 
	  else
	    begin    
	      // When there is a valid read address (S_AXI_ARVALID) with 
	      // acceptance of read address by the slave (axi_arready), 
	      // output the read dada 
	      if (slv_reg_rden)
	        begin
	          axi_rdata <= reg_data_out;     // register read data
	        end   
	    end
	end

	// Store ED25519_mul output in key register
	always @(posedge S_AXI_ACLK) begin
    if (S_AXI_ARESETN == 1'b0) begin
        qy_reg <= 256'h0;
    end else if (QY_WREN) begin
        qy_reg[QY_ADDR * 32 +: 32] <= QY_DOUT;
    end
	end

	// Store ED25519_sign output in core_s_reg
	always @(posedge S_AXI_ACLK) begin
	if (S_AXI_ARESETN == 1'b0) begin
		core_s_reg <= 256'h0;
	end else if (CORE_COMP_DONE) begin
		core_s_reg <= CORE_S;
	end
	end


	// Update ED25519 control signals from status_reg
	always @(posedge S_AXI_ACLK) begin
		if (S_AXI_ARESETN == 1'b0) begin
			ENA <= 1'b0;
		end else begin
			ENA <= status_reg[0];
		end
	end

	// Update ED25519 control signals from status3_reg
	always @(posedge S_AXI_ACLK) begin
		if (S_AXI_ARESETN == 1'b0) begin
			CORE_ENA <= 1'b0;
		end else if(CORE_COMP_DONE == 1'b1) begin
			CORE_ENA <= 1'b0;
		end else begin
			CORE_ENA <= status3_reg[0];
		end
	end


	// Update input to ED25519_mul
	always @(posedge S_AXI_ACLK) begin
		if (S_AXI_ARESETN == 1'b0) begin
			k_din_reg <= 31'h0;
		end else begin
			k_din_reg <= k_reg[K_ADDR * 32 +: 32];
		end
	end

endmodule