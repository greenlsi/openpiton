`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 02/20/2025 10:19:35 AM
// Design Name: 
// Module Name: sha3_axi_wrapper
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


module sha3_axi_wrapper #(
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

    // SHA3 Signals
    output reg        S_SHA3_IRST,
    output reg         S_SHA3_IREADY,
    output reg         S_SHA3_ILAST,
    output reg  [2:0]  S_SHA3_IBYTE_NUM,
    output wire  [63:0] S_SHA3_IDATA,
    input  wire        S_SHA3_OBUFFER_FULL,
    input  wire [511:0] S_SHA3_ODATA,
    input  wire        S_SHA3_OREADY
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
	localparam integer OPT_MEM_ADDR_BITS = 4;
	//----------------------------------------------
	//-- Signals for user logic register space example
	//------------------------------------------------
	//-- Number of Slave Registers: 
    // 1 data in (64 bits) + 1 status (it is 32 bits but for bus coherence it is declared as 64 bits) + 8 data out (hash is 16 registers*32bits = 512 bits, so 8 registers of 64 bits are enough)

    reg [63:0] data_in_reg;
    reg [63:0] status_reg;
    reg [63:0] hash_data_out_0_reg;
    reg [63:0] hash_data_out_1_reg;
    reg [63:0] hash_data_out_2_reg;
    reg [63:0] hash_data_out_3_reg;
    reg [63:0] hash_data_out_4_reg;
    reg [63:0] hash_data_out_5_reg;
    reg [63:0] hash_data_out_6_reg;
    reg [63:0] hash_data_out_7_reg;

    wire	 slv_reg_rden;
	wire	 slv_reg_wren;
	reg [63:0]	 reg_data_out;
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

	assign S_SHA3_IDATA = data_in_reg;

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
	assign slv_reg_wren = axi_wready && S_AXI_WVALID && axi_awready && S_AXI_AWVALID;

    always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      data_in_reg <= 0;
		  status_reg <= 0;
	    end         
	  else begin
	    if (slv_reg_wren)
	      begin

			//Register addresses:
			//data_in_reg 0x64003000
			//status_reg 0x64003008
			//hash_data_out 0x64003040

			//Only for input registers in which we need to write, hash_data_out is not written by the master
			//Taking axi_awaddr[3+4:3] = axi_awaddr[7:3]
			//data_in_reg[7:3] = 00000 = 5'h00
			//status_reg[7:3] = 00001 = 5'h01
			
	        case ( axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] )
	          5'h00:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // data_in_reg
	                data_in_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h01:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 ) begin
					if ( S_AXI_WSTRB[byte_index] == 1 ) begin
						if ( byte_index == 1 ) begin
							status_reg[(byte_index*8) +: 8] <= (S_AXI_WDATA[(byte_index*8) +: 8] & ~8'b00000111) | (status_reg[(byte_index*8) +: 8] & 8'b00000111);
						end else begin
							// Respective byte enables are asserted as per write strobes 
							// status_reg
							status_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
						end
					end
				end

	          default : begin
	                      data_in_reg <= data_in_reg;
	                      status_reg <= status_reg;
	                    end
	        endcase
		end

		  	// Update read-only bits of status_reg
			status_reg[8] <= S_SHA3_OBUFFER_FULL || !S_SHA3_OREADY;
			status_reg[9] <= S_SHA3_OBUFFER_FULL;
			status_reg[10] <= !S_SHA3_OREADY;
			
			//Set iready to 0 after one clock cycle
			if (status_reg[16] == 1'b1) begin
                status_reg[16] <= 1'b0;
            end

			// Set ilasy to 0 after one clock cycle
			if (status_reg[17] == 1'b1) begin
                status_reg[17] <= 1'b0;
            end
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
	assign slv_reg_rden = axi_arready & S_AXI_ARVALID & ~axi_rvalid;
	always @(*)
	begin
	      // Address decoding for reading registers

		  //hash_data_out_0_reg 0x64003040, [7:3] = 01000 = 5'h08
		  //hash_data_out_1_reg 0x64003048, [7:3] = 01001 = 5'h09
		  //hash_data_out_2_reg 0x64003050, [7:3] = 01010 = 5'h0A
		  //hash_data_out_3_reg 0x64003058, [7:3] = 01011 = 5'h0B
		  //hash_data_out_4_reg 0x64003060, [7:3] = 01100 = 5'h0C
		  //hash_data_out_5_reg 0x64003068, [7:3] = 01101 = 5'h0D
		  //hash_data_out_6_reg 0x64003070, [7:3] = 01110 = 5'h0E
		  //hash_data_out_7_reg 0x64003078, [7:3] = 01111 = 5'h0F

	      case ( axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] )
		    5'h00   : reg_data_out <= data_in_reg;
		    5'h01   : reg_data_out <= status_reg;
	        5'h08   : reg_data_out <= hash_data_out_0_reg;
	        5'h09   : reg_data_out <= hash_data_out_1_reg;
	        5'h0A   : reg_data_out <= hash_data_out_2_reg;
	        5'h0B   : reg_data_out <= hash_data_out_3_reg;
	        5'h0C   : reg_data_out <= hash_data_out_4_reg;
	        5'h0D   : reg_data_out <= hash_data_out_5_reg;
	        5'h0E   : reg_data_out <= hash_data_out_6_reg;
	        5'h0F   : reg_data_out <= hash_data_out_7_reg;
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

	// Store SHA3 output in 64 bit registers
	always @(posedge S_AXI_ACLK) begin
    if (S_AXI_ARESETN == 1'b0) begin
        hash_data_out_0_reg <= 64'b0;
        hash_data_out_1_reg <= 64'b0;
        hash_data_out_2_reg <= 64'b0;
        hash_data_out_3_reg <= 64'b0;
        hash_data_out_4_reg <= 64'b0;
        hash_data_out_5_reg <= 64'b0;
        hash_data_out_6_reg <= 64'b0;
        hash_data_out_7_reg <= 64'b0;
    end else if (S_SHA3_OREADY) begin
        hash_data_out_0_reg <= S_SHA3_ODATA[63:0];
        hash_data_out_1_reg <= S_SHA3_ODATA[127:64];
        hash_data_out_2_reg <= S_SHA3_ODATA[191:128];
        hash_data_out_3_reg <= S_SHA3_ODATA[255:192];
        hash_data_out_4_reg <= S_SHA3_ODATA[319:256];
        hash_data_out_5_reg <= S_SHA3_ODATA[383:320];
        hash_data_out_6_reg <= S_SHA3_ODATA[447:384];
        hash_data_out_7_reg <= S_SHA3_ODATA[511:448];
    end
	end

	// Update SHA3 control signals from status_reg
	always @(posedge S_AXI_ACLK) begin
		if (S_AXI_ARESETN == 1'b0) begin
			S_SHA3_IBYTE_NUM <= 3'b0;
			S_SHA3_IREADY <= 1'b0;
			S_SHA3_ILAST <= 1'b0;
			S_SHA3_IRST <= 1'b1;
		end else begin
			S_SHA3_IBYTE_NUM <= status_reg[2:0];
			S_SHA3_IREADY <= status_reg[16];
			S_SHA3_ILAST <= status_reg[17];
			S_SHA3_IRST <= status_reg[18];
		end
	end

endmodule