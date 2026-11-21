module llbc128 (
    input wire decrypt,
    input wire [127:0] block_in,
    input wire [127:0] key,
    output reg [127:0] block_out
);
    localparam integer ROUNDS = 20;
    localparam [31:0] RC0_32 = 32'h243F6A88;

    reg [63:0] kw [0:20];
    reg [63:0] l, r, t, y1, y2, m;
    reg [63:0] prev_l, prev_r;
    integer i;

    function [31:0] rol32;
        input [31:0] x;
        input integer amount;
        integer s;
        begin
            s = amount % 32;
            if (s == 0) rol32 = x;
            else rol32 = (x << s) | (x >> (32 - s));
        end
    endfunction

    function [63:0] round_constant;
        input integer round_index;
        begin
            round_constant = {rol32(RC0_32, round_index), 32'b0};
        end
    endfunction

    function [63:0] rol64;
        input [63:0] x;
        input integer amount;
        integer s;
        begin
            s = amount % 64;
            if (s == 0) rol64 = x;
            else rol64 = (x << s) | (x >> (64 - s));
        end
    endfunction

    function [15:0] rol16;
        input [15:0] x;
        input integer amount;
        integer s;
        begin
            s = amount % 16;
            if (s == 0) rol16 = x;
            else rol16 = (x << s) | (x >> (16 - s));
        end
    endfunction

    function [3:0] sbox1;
        input [3:0] x;
        begin
            case (x)
                4'h0:sbox1=4'h4; 4'h1:sbox1=4'h7; 4'h2:sbox1=4'h5; 4'h3:sbox1=4'h1;
                4'h4:sbox1=4'hC; 4'h5:sbox1=4'hB; 4'h6:sbox1=4'hD; 4'h7:sbox1=4'h8;
                4'h8:sbox1=4'hE; 4'h9:sbox1=4'hF; 4'hA:sbox1=4'h6; 4'hB:sbox1=4'h3;
                4'hC:sbox1=4'hA; 4'hD:sbox1=4'h9; 4'hE:sbox1=4'h2; 4'hF:sbox1=4'h0;
                default:sbox1=4'h0;
            endcase
        end
    endfunction

    function [3:0] sbox2;
        input [3:0] x;
        begin
            case (x)
                4'h0:sbox2=4'hE; 4'h1:sbox2=4'hC; 4'h2:sbox2=4'h8; 4'h3:sbox2=4'h4;
                4'h4:sbox2=4'hB; 4'h5:sbox2=4'hD; 4'h6:sbox2=4'h1; 4'h7:sbox2=4'h5;
                4'h8:sbox2=4'hF; 4'h9:sbox2=4'h3; 4'hA:sbox2=4'hA; 4'hB:sbox2=4'h2;
                4'hC:sbox2=4'h9; 4'hD:sbox2=4'h7; 4'hE:sbox2=4'h0; 4'hF:sbox2=4'h6;
                default:sbox2=4'h0;
            endcase
        end
    endfunction

    function [63:0] sub1_layer;
        input [63:0] x;
        integer n;
        begin
            for (n = 0; n < 16; n = n + 1)
                sub1_layer[4*n +: 4] = sbox1(x[4*n +: 4]);
        end
    endfunction

    function [63:0] sub2_layer;
        input [63:0] x;
        integer n;
        begin
            for (n = 0; n < 16; n = n + 1)
                sub2_layer[4*n +: 4] = sbox2(x[4*n +: 4]);
        end
    endfunction

    function [63:0] g64;
        input [63:0] x;
        reg [15:0] a, b, c, d, ra, rb;
        begin
            a = x[63:48];
            b = x[47:32];
            c = x[31:16];
            d = x[15:0];
            ra = rol16(a, 3);
            rb = rol16(b, 1);
            g64 = {ra ^ c, rb ^ d, ra, rb};
        end
    endfunction

    function [63:0] mixword;
        input [63:0] ml;
        input [63:0] mr;
        reg [63:0] x, t0, t1, u;
        begin
            x = ml ^ mr;
            t0 = rol64(x, 3) ^ ml;
            t1 = rol64(t0, 19) ^ x;
            u = rol64(t1, 3) ^ t0;
            mixword = u ^ rol64(u, 19) ^ t1;
        end
    endfunction

    always @* begin
        kw[0] = key[127:64];
        kw[1] = key[63:0];
        for (i = 0; i < ROUNDS - 1; i = i + 1)
            kw[i+2] = g64(g64(kw[i+1])) ^ kw[i] ^ round_constant(i);

        l = block_in[127:64];
        r = block_in[63:0];
        t = 64'b0;
        y1 = 64'b0;
        y2 = 64'b0;
        m = 64'b0;
        prev_l = 64'b0;
        prev_r = 64'b0;

        if (!decrypt) begin
            for (i = 0; i < ROUNDS; i = i + 1) begin
                t = l ^ kw[i+1] ^ round_constant(i);
                y1 = sub1_layer(rol64(l, 3));
                y2 = sub2_layer(rol64(t, 19));
                m = mixword(y1, y2);
                prev_l = m ^ r ^ kw[i];
                l = prev_l;
                r = t;
            end
        end else begin
            for (i = ROUNDS - 1; i >= 0; i = i - 1) begin
                prev_l = r ^ kw[i+1] ^ round_constant(i);
                y1 = sub1_layer(rol64(prev_l, 3));
                y2 = sub2_layer(rol64(r, 19));
                m = mixword(y1, y2);
                prev_r = l ^ m ^ kw[i];
                l = prev_l;
                r = prev_r;
            end
        end

        block_out = {l, r};
    end
endmodule
