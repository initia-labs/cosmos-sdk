package ante_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/log"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
)

// recordingAnteHandler returns an AnteHandler that sets *called to true when invoked.
func recordingAnteHandler(called *bool) sdk.AnteHandler {
	return func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		*called = true
		return ctx, nil
	}
}

// failingAnteHandler returns an AnteHandler that always returns the given error.
func failingAnteHandler(err error) sdk.AnteHandler {
	return func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		return ctx, err
	}
}

func TestNewMinimalAnteHandler_Validation(t *testing.T) {
	t.Run("nil AccountKeeper returns error", func(t *testing.T) {
		_, err := ante.NewMinimalAnteHandler(ante.MinimalHandlerOptions{
			AccountKeeper:   nil,
			SignModeHandler: nil,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "account keeper is required")
	})

	t.Run("nil SignModeHandler returns error", func(t *testing.T) {
		// We need a non-nil AccountKeeper but nil SignModeHandler
		suite := SetupTestSuite(t, false)
		_, err := ante.NewMinimalAnteHandler(ante.MinimalHandlerOptions{
			AccountKeeper:   suite.accountKeeper,
			SignModeHandler: nil,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "sign mode handler is required")
	})

	t.Run("valid options returns no error", func(t *testing.T) {
		suite := SetupTestSuite(t, false)
		handler, err := ante.NewMinimalAnteHandler(ante.MinimalHandlerOptions{
			AccountKeeper:   suite.accountKeeper,
			SignModeHandler: suite.clientCtx.TxConfig.SignModeHandler(),
			SigGasConsumer:  ante.DefaultSigVerificationGasConsumer,
		})
		require.NoError(t, err)
		require.NotNil(t, handler)
	})
}

func TestNewDualAnteHandler_Routing(t *testing.T) {
	t.Run("CheckTx context routes to minimal handler", func(t *testing.T) {
		var minimalCalled, fullCalled bool
		dual := ante.NewDualAnteHandler(
			recordingAnteHandler(&minimalCalled),
			recordingAnteHandler(&fullCalled),
		)

		ctx := sdk.NewContext(nil, cmtproto.Header{}, false, log.NewNopLogger()).WithIsCheckTx(true)
		_, err := dual(ctx, nil, false)
		require.NoError(t, err)
		require.True(t, minimalCalled)
		require.False(t, fullCalled)
	})

	t.Run("ReCheckTx context routes to minimal handler", func(t *testing.T) {
		var minimalCalled, fullCalled bool
		dual := ante.NewDualAnteHandler(
			recordingAnteHandler(&minimalCalled),
			recordingAnteHandler(&fullCalled),
		)

		ctx := sdk.NewContext(nil, cmtproto.Header{}, false, log.NewNopLogger()).WithIsReCheckTx(true)
		_, err := dual(ctx, nil, false)
		require.NoError(t, err)
		require.True(t, minimalCalled)
		require.False(t, fullCalled)
	})

	t.Run("normal context routes to full handler", func(t *testing.T) {
		var minimalCalled, fullCalled bool
		dual := ante.NewDualAnteHandler(
			recordingAnteHandler(&minimalCalled),
			recordingAnteHandler(&fullCalled),
		)

		ctx := sdk.NewContext(nil, cmtproto.Header{}, false, log.NewNopLogger())
		_, err := dual(ctx, nil, false)
		require.NoError(t, err)
		require.False(t, minimalCalled)
		require.True(t, fullCalled)
	})
}

func TestNewDualAnteHandler_ErrorPropagation(t *testing.T) {
	t.Run("minimal error returned during CheckTx", func(t *testing.T) {
		expectedErr := errorsmod.Wrap(sdkerrors.ErrUnauthorized, "minimal failed")
		dual := ante.NewDualAnteHandler(
			failingAnteHandler(expectedErr),
			recordingAnteHandler(new(bool)),
		)

		ctx := sdk.NewContext(nil, cmtproto.Header{}, false, log.NewNopLogger()).WithIsCheckTx(true)
		_, err := dual(ctx, nil, false)
		require.Error(t, err)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
	})

	t.Run("full error returned during normal execution", func(t *testing.T) {
		expectedErr := errorsmod.Wrap(sdkerrors.ErrInsufficientFee, "full failed")
		dual := ante.NewDualAnteHandler(
			recordingAnteHandler(new(bool)),
			failingAnteHandler(expectedErr),
		)

		ctx := sdk.NewContext(nil, cmtproto.Header{}, false, log.NewNopLogger())
		_, err := dual(ctx, nil, false)
		require.Error(t, err)
		require.ErrorIs(t, err, sdkerrors.ErrInsufficientFee)
	})
}
