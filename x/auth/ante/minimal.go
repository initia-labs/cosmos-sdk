package ante

import (
	errorsmod "cosmossdk.io/errors"
	txsigning "cosmossdk.io/x/tx/signing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// MinimalHandlerOptions are the options required for constructing a minimal
// AnteHandler used during CheckTx. This handler performs signature verification,
// format validation, and gas limit checks but does not deduct fees or increment
// the account sequence, those are handled during PrepareProposal/FinalizeBlock
// by the full AnteHandler.
type MinimalHandlerOptions struct {
	AccountKeeper   AccountKeeper
	SignModeHandler *txsigning.HandlerMap
	SigGasConsumer  SignatureVerificationGasConsumer
}

// NewMinimalAnteHandler returns a reduced AnteHandler chain for CheckTx mode.
// It verifies signatures, validates basic tx format, and enforces gas limits.
func NewMinimalAnteHandler(opts MinimalHandlerOptions) (sdk.AnteHandler, error) {
	if opts.AccountKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "account keeper is required for minimal ante handler")
	}
	if opts.SignModeHandler == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "sign mode handler is required for minimal ante handler")
	}

	anteDecorators := []sdk.AnteDecorator{
		NewSetUpContextDecorator(),
		NewValidateBasicDecorator(),
		NewConsumeGasForTxSizeDecorator(opts.AccountKeeper),
		NewSetPubKeyDecorator(opts.AccountKeeper),
		NewValidateSigCountDecorator(opts.AccountKeeper),
		NewSigGasConsumeDecorator(opts.AccountKeeper, opts.SigGasConsumer),
		NewSigVerificationDecorator(opts.AccountKeeper, opts.SignModeHandler),
		// no DeductFeeDecorator, fees deducted during PrepareProposal/FinalizeBlock
		// no IncrementSequenceDecorator, mempool tracks nonces
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}

// NewDualAnteHandler returns an AnteHandler that routes to the minimal handler
// during CheckTx/ReCheckTx and to the full handler during PrepareProposal/ProcessProposal/FinalizeBlock.
func NewDualAnteHandler(minimal, full sdk.AnteHandler) sdk.AnteHandler {
	return func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		if ctx.IsCheckTx() || ctx.IsReCheckTx() {
			return minimal(ctx, tx, simulate)
		}
		return full(ctx, tx, simulate)
	}
}
