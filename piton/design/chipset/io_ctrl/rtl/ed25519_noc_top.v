`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 03/06/2025 10:38:32 AM
// Design Name: 
// Module Name: ed25519_noc_top
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
`include "define.tmp.h"
`define C_M_AXI_LITE_DATA_WIDTH  `NOC_DATA_WIDTH
`define C_M_AXI_LITE_ADDR_WIDTH  `NOC_DATA_WIDTH
`define C_M_AXI_LITE_RESP_WIDTH  2
// this is non-standard
`define C_M_AXI_LITE_SIZE_WIDTH  3

module ed25519_noc_top #(
    parameter SLAVE_RESP_BYTEWIDTH = 0,
    parameter SWAP_ENDIANESS       = 0,
    parameter ALIGN_RDATA          = 1
    )(
    // Clock + Reset
    input  wire                                   clk,
    input  wire                                   rst,

    // receive request/send response
    input                                   xbar_ed25519_noc2_valid,
    input [`NOC_DATA_WIDTH-1:0]             xbar_ed25519_noc2_data,     
    output                                  ed25519_xbar_noc2_ready,

    output                                  ed25519_xbar_noc3_valid,
    output [`NOC_DATA_WIDTH-1:0]            ed25519_xbar_noc3_data,  
    input                                   xbar_ed25519_noc3_ready
    );


    //AXI Signals
    localparam C_S_AXI_DATA_WIDTH = 64;
    localparam C_S_AXI_ADDR_WIDTH = 64;

    // AXI Write Address Channel
    wire [C_S_AXI_ADDR_WIDTH-1:0]       S_AXI_AWADDR;
    wire [2 : 0]                        S_AXI_AWPROT;
    wire                                S_AXI_AWVALID;
    wire                                S_AXI_AWREADY;

    // AXI Write Data Channel
    wire [C_S_AXI_DATA_WIDTH-1:0]       S_AXI_WDATA;
    wire [(C_S_AXI_DATA_WIDTH/8)-1:0]   S_AXI_WSTRB;
    wire                                S_AXI_WVALID;
    wire                                S_AXI_WREADY;

    // AXI Write Response Channel
    wire [1:0]                          S_AXI_BRESP;
    wire                                S_AXI_BVALID;
    wire                                S_AXI_BREADY;

    // AXI Read Address Channel
    wire [C_S_AXI_ADDR_WIDTH-1:0]       S_AXI_ARADDR;
    wire [2 : 0]                        S_AXI_ARPROT;
    wire                                S_AXI_ARVALID;
    wire                                S_AXI_ARREADY;

    // AXI Read Data Channel
    wire [C_S_AXI_DATA_WIDTH-1:0]       S_AXI_RDATA;
    wire [1:0]                          S_AXI_RRESP;
    wire                                S_AXI_RVALID;
    wire                                S_AXI_RREADY;


    //NoC AXI-Lite Bridge
    noc_axilite_bridge #(
        .SLAVE_RESP_BYTEWIDTH   (SLAVE_RESP_BYTEWIDTH ),
        .SWAP_ENDIANESS         (SWAP_ENDIANESS       ),    
        .ALIGN_RDATA            (ALIGN_RDATA          )
    ) noc_axilite_ed25519_bridge_i (
        .clk                    (clk                  ),
        .rst                    (rst                  ),

        .splitter_bridge_val    (xbar_ed25519_noc2_valid  ),
        .splitter_bridge_data   (xbar_ed25519_noc2_data ),
        .bridge_splitter_rdy    (ed25519_xbar_noc2_ready  ),

        .bridge_splitter_val    (ed25519_xbar_noc3_valid  ),
        .bridge_splitter_data   (ed25519_xbar_noc3_data ),
        .splitter_bridge_rdy    (xbar_ed25519_noc3_ready  ),
        //axi lite signals             
        //write address channel
        .m_axi_awaddr           (S_AXI_AWADDR         ),
        .m_axi_awvalid          (S_AXI_AWVALID        ),
        .m_axi_awready          (S_AXI_AWREADY        ),
        //write data channel
        .m_axi_wdata            (S_AXI_WDATA          ),
        .m_axi_wstrb            (S_AXI_WSTRB          ),
        .m_axi_wvalid           (S_AXI_WVALID         ),
        .m_axi_wready           (S_AXI_WREADY         ),
        //read address channel
        .m_axi_araddr           (S_AXI_ARADDR         ),
        .m_axi_arvalid          (S_AXI_ARVALID        ),
        .m_axi_arready          (S_AXI_ARREADY        ),
        //read data channel
        .m_axi_rdata            (S_AXI_RDATA          ),
        .m_axi_rresp            (S_AXI_RRESP          ),
        .m_axi_rvalid           (S_AXI_RVALID         ),
        .m_axi_rready           (S_AXI_RREADY         ),
        //write response channel
        .m_axi_bresp            (S_AXI_BRESP          ),
        .m_axi_bvalid           (S_AXI_BVALID         ),
        .m_axi_bready           (S_AXI_BREADY         )
        // non-axi-lite signals
        // .w_reqbuf_size          (                     ),
        // .r_reqbuf_size          (                     )
    );


    // Internal wires to connect axi_ed25519_wrapper and ed25519_mul_TOP_wrapper
    wire [31:0] K_DIN;
    wire ENA;
    wire [31:0] QY_DOUT;
    wire RDY;
    wire [2:0] K_ADDR;
    wire [2:0] QY_ADDR;
    wire QY_WREN;

    // Internal wires to connect axi_ed25519_wrapper and ed25519_sign_S_core_TOP_wrapper
    wire CORE_ENA;
    wire [511:0] HASHD_KEY;
    wire [511:0] HASHD_RAM;
    wire [511:0] HASHD_SM;
    wire CORE_READY;
    wire CORE_COMP_DONE;
    wire [255:0] CORE_S;


    ed25519_axi_wrapper #(
        .C_S_AXI_DATA_WIDTH     (C_S_AXI_DATA_WIDTH),
        .C_S_AXI_ADDR_WIDTH     (C_S_AXI_ADDR_WIDTH)
    ) ed_25519_axi_wrapper_i (
        .S_AXI_ACLK             (clk              ),
        .S_AXI_ARESETN          (~rst             ),
        .S_AXI_AWADDR           (S_AXI_AWADDR     ),
        .S_AXI_AWPROT           (3'b000           ),
        .S_AXI_AWVALID          (S_AXI_AWVALID    ),
        .S_AXI_AWREADY          (S_AXI_AWREADY    ),
        .S_AXI_WDATA            (S_AXI_WDATA      ),
        .S_AXI_WSTRB            (S_AXI_WSTRB      ),
        .S_AXI_WVALID           (S_AXI_WVALID     ),
        .S_AXI_WREADY           (S_AXI_WREADY     ),
        .S_AXI_BRESP            (S_AXI_BRESP      ),
        .S_AXI_BVALID           (S_AXI_BVALID     ),
        .S_AXI_BREADY           (S_AXI_BREADY     ),
        .S_AXI_ARADDR           (S_AXI_ARADDR     ),
        .S_AXI_ARPROT           (3'b000           ),
        .S_AXI_ARVALID          (S_AXI_ARVALID    ),
        .S_AXI_ARREADY          (S_AXI_ARREADY    ),
        .S_AXI_RDATA            (S_AXI_RDATA      ),
        .S_AXI_RRESP            (S_AXI_RRESP      ),
        .S_AXI_RVALID           (S_AXI_RVALID     ),
        .S_AXI_RREADY           (S_AXI_RREADY     ),
        .K_DIN                  (K_DIN            ),
        .ENA                    (ENA              ),
        .QY_DOUT                (QY_DOUT          ),
        .RDY                    (RDY              ),
        .K_ADDR                 (K_ADDR           ),
        .QY_ADDR                (QY_ADDR          ),
        .QY_WREN                (QY_WREN          ),
        .CORE_ENA               (CORE_ENA         ),
        .HASHD_KEY              (HASHD_KEY        ),
        .HASHD_RAM              (HASHD_RAM        ),
        .HASHD_SM               (HASHD_SM         ),
        .CORE_READY             (CORE_READY       ),
        .CORE_COMP_DONE         (CORE_COMP_DONE   ),
        .CORE_S                 (CORE_S           )
    );

    ed25519_mul_TOP_wrapper ed25519_mul_TOP_wrapper_i (
        .clk(clk),
        .rst_n(~rst),
        .ena(ENA),
        .rdy(RDY),
        .k_addr(K_ADDR),
        .qy_addr(QY_ADDR),
        .qy_wren(QY_WREN),
        .k_din(K_DIN),
        .qy_dout(QY_DOUT)
    );

    ed25519_sign_S_core_TOP_wrapper ed25519_sign_S_core_TOP_wrapper_i (
        .clk(clk),
        .rst(rst),
        .core_ena(CORE_ENA),
        .core_ready(CORE_READY),
        .core_comp_done(CORE_COMP_DONE),
        .hashd_key(HASHD_KEY),
        .hashd_ram(HASHD_RAM),
        .hashd_sm(HASHD_SM),
        .core_S(CORE_S)
    );
endmodule
